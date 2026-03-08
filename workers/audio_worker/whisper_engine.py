"""
Healthcare Privacy Firewall — Whisper Audio Transcription Engine
Transcribes audio files using OpenAI Whisper for downstream PII detection.
"""

import os
import logging
import tempfile
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)

WHISPER_MODEL = os.getenv("WHISPER_MODEL", "base")
WHISPER_LANGUAGE = os.getenv("WHISPER_LANGUAGE", "en")


class WhisperEngine:
    """
    Transcribes audio files using OpenAI Whisper model.
    Extracts text content for downstream PII/PHI scanning.
    """

    def __init__(
        self,
        model_name: str = WHISPER_MODEL,
        language: str = WHISPER_LANGUAGE,
        device: Optional[str] = None,
    ):
        self.model_name = model_name
        self.language = language
        self.device = device or "cpu"
        self._model = None

    def _load_model(self):
        """Lazy-load the Whisper model."""
        if self._model is not None:
            return self._model

        try:
            import whisper

            logger.info(f"Loading Whisper model: {self.model_name} on {self.device}")
            self._model = whisper.load_model(self.model_name, device=self.device)
            logger.info("Whisper model loaded successfully")
            return self._model
        except ImportError:
            raise RuntimeError(
                "openai-whisper is not installed. Install with: pip install openai-whisper"
            )
        except Exception as e:
            logger.error(f"Failed to load Whisper model: {e}")
            raise

    def transcribe(
        self,
        audio_path: str,
        language: Optional[str] = None,
        task: str = "transcribe",
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """
        Transcribe an audio file to text.

        Args:
            audio_path: Path to the audio file
            language: Language code (e.g., 'en'). Auto-detect if None.
            task: 'transcribe' or 'translate'
            verbose: Whether to show progress

        Returns:
            Dict with text, segments, language, and duration metadata.
        """
        path = Path(audio_path)
        if not path.exists():
            raise FileNotFoundError(f"Audio file not found: {audio_path}")

        model = self._load_model()

        try:
            logger.info(f"Transcribing audio: {path.name}")

            result = model.transcribe(
                str(path),
                language=language or self.language,
                task=task,
                verbose=verbose,
                fp16=False,  # CPU compatibility
            )

            # Extract segments with timestamps
            segments = []
            for seg in result.get("segments", []):
                segments.append({
                    "id": seg.get("id", 0),
                    "start": round(seg.get("start", 0), 2),
                    "end": round(seg.get("end", 0), 2),
                    "text": seg.get("text", "").strip(),
                    "avg_logprob": round(seg.get("avg_logprob", 0), 4),
                    "no_speech_prob": round(seg.get("no_speech_prob", 0), 4),
                })

            # Calculate overall confidence
            avg_logprob = (
                sum(s["avg_logprob"] for s in segments) / len(segments)
                if segments
                else 0
            )

            transcription = {
                "text": result.get("text", "").strip(),
                "language": result.get("language", self.language),
                "segments": segments,
                "segment_count": len(segments),
                "duration_seconds": segments[-1]["end"] if segments else 0,
                "word_count": len(result.get("text", "").split()),
                "avg_logprob": round(avg_logprob, 4),
            }

            logger.info(
                f"Transcription complete: {transcription['word_count']} words, "
                f"{transcription['duration_seconds']}s duration"
            )
            return transcription

        except Exception as e:
            logger.error(f"Transcription failed for {audio_path}: {e}")
            raise

    def transcribe_bytes(
        self, audio_bytes: bytes, format: str = "wav"
    ) -> Dict[str, Any]:
        """Transcribe audio from bytes (for API uploads)."""
        with tempfile.NamedTemporaryFile(
            suffix=f".{format}", delete=False
        ) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name

        try:
            return self.transcribe(tmp_path)
        finally:
            os.unlink(tmp_path)

    def get_text_with_timestamps(
        self, transcription: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Get text segments with their timestamps.
        Useful for pinpointing when PII was spoken in the audio.
        """
        return [
            {
                "text": seg["text"],
                "start_time": seg["start"],
                "end_time": seg["end"],
            }
            for seg in transcription.get("segments", [])
            if seg["text"].strip()
        ]


# Module-level singleton
_engine: Optional[WhisperEngine] = None


def get_whisper_engine() -> WhisperEngine:
    global _engine
    if _engine is None:
        _engine = WhisperEngine()
    return _engine
