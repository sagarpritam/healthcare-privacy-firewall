"""
Healthcare Privacy Firewall — OCR Engine
Extracts text from images using Tesseract OCR for downstream PII detection.
"""

import os
import logging
import tempfile
from typing import Optional, Dict, Any, List
from pathlib import Path

try:
    from PIL import Image, ImageFilter, ImageEnhance
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

logger = logging.getLogger(__name__)

TESSERACT_CMD = os.getenv("TESSERACT_CMD", "tesseract")
OCR_LANGUAGE = os.getenv("OCR_LANGUAGE", "eng")
OCR_DPI = int(os.getenv("OCR_DPI", "300"))


class OCREngine:
    """
    Extracts text from images using Tesseract OCR.
    Supports preprocessing for improved accuracy on medical documents.
    """

    def __init__(
        self,
        tesseract_cmd: Optional[str] = None,
        language: str = OCR_LANGUAGE,
        dpi: int = OCR_DPI,
    ):
        self.language = language
        self.dpi = dpi

        if TESSERACT_AVAILABLE and tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

    def extract_text(
        self,
        image_path: str,
        preprocess: bool = True,
        config: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Extract text from an image file.

        Returns dict with extracted text, confidence, word count, and metadata.
        """
        if not TESSERACT_AVAILABLE:
            raise RuntimeError("pytesseract is not installed. Install with: pip install pytesseract")
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is not installed. Install with: pip install Pillow")

        path = Path(image_path)
        if not path.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")

        try:
            image = Image.open(image_path)

            if preprocess:
                image = self._preprocess_image(image)

            # OCR configuration
            ocr_config = config or f"--dpi {self.dpi} --oem 3 --psm 6"

            # Extract text
            text = pytesseract.image_to_string(
                image, lang=self.language, config=ocr_config
            )

            # Get detailed data for confidence scoring
            data = pytesseract.image_to_data(
                image, lang=self.language, config=ocr_config, output_type=pytesseract.Output.DICT
            )

            # Calculate average confidence
            confidences = [
                int(c) for c in data.get("conf", []) if str(c).isdigit() and int(c) > 0
            ]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

            # Extract word bounding boxes for potential redaction
            words_with_positions = []
            for i in range(len(data.get("text", []))):
                word = data["text"][i].strip()
                if word:
                    words_with_positions.append({
                        "text": word,
                        "left": data["left"][i],
                        "top": data["top"][i],
                        "width": data["width"][i],
                        "height": data["height"][i],
                        "confidence": int(data["conf"][i]) if str(data["conf"][i]).isdigit() else 0,
                    })

            result = {
                "text": text.strip(),
                "confidence": round(avg_confidence, 2),
                "word_count": len([w for w in text.split() if w.strip()]),
                "image_size": image.size,
                "words_with_positions": words_with_positions,
            }

            logger.info(
                f"OCR extracted {result['word_count']} words from {path.name} "
                f"(confidence: {result['confidence']}%)"
            )
            return result

        except Exception as e:
            logger.error(f"OCR extraction failed for {image_path}: {e}")
            raise

    def _preprocess_image(self, image: Image.Image) -> Image.Image:
        """Preprocess image for better OCR accuracy."""
        # Convert to grayscale
        if image.mode != "L":
            image = image.convert("L")

        # Enhance contrast
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(2.0)

        # Enhance sharpness
        enhancer = ImageEnhance.Sharpness(image)
        image = enhancer.enhance(2.0)

        # Apply slight denoise
        image = image.filter(ImageFilter.MedianFilter(size=3))

        # Resize for better OCR if too small
        width, height = image.size
        if width < 1000:
            scale = 1000 / width
            image = image.resize(
                (int(width * scale), int(height * scale)),
                Image.LANCZOS,
            )

        return image

    def extract_text_from_bytes(
        self, image_bytes: bytes, preprocess: bool = True
    ) -> Dict[str, Any]:
        """Extract text from image bytes (for API uploads)."""
        import io

        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is not installed")

        image = Image.open(io.BytesIO(image_bytes))
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            image.save(tmp.name)
            try:
                return self.extract_text(tmp.name, preprocess=preprocess)
            finally:
                os.unlink(tmp.name)


# Module-level singleton
_engine: Optional[OCREngine] = None


def get_ocr_engine() -> OCREngine:
    global _engine
    if _engine is None:
        _engine = OCREngine()
    return _engine
