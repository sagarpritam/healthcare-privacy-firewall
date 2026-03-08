"""
Healthcare Privacy Firewall — Image Blur Engine
Blurs/redacts regions in images where PII/PHI text was detected.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFilter
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class ImageBlurEngine:
    """Blurs or redacts regions in images containing detected PII/PHI."""

    def __init__(
        self,
        blur_radius: int = 30,
        redact_color: Tuple[int, int, int] = (0, 0, 0),
        padding: int = 5,
    ):
        self.blur_radius = blur_radius
        self.redact_color = redact_color
        self.padding = padding

    def blur_regions(
        self,
        image_path: str,
        regions: List[Dict[str, int]],
        output_path: Optional[str] = None,
        mode: str = "blur",
    ) -> str:
        """
        Blur or redact specified regions in an image.

        Args:
            image_path: Path to source image
            regions: List of dicts with left, top, width, height keys
            output_path: Where to save the result (defaults to *_masked.png)
            mode: "blur" for gaussian blur, "redact" for black box

        Returns:
            Path to the output image
        """
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is not installed")

        path = Path(image_path)
        if not path.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")

        image = Image.open(image_path).convert("RGB")
        masked_image = image.copy()

        if mode == "blur":
            masked_image = self._apply_blur(masked_image, regions)
        elif mode == "redact":
            masked_image = self._apply_redaction(masked_image, regions)
        else:
            raise ValueError(f"Unknown mode: {mode}. Use 'blur' or 'redact'.")

        # Save result
        if output_path is None:
            output_path = str(path.parent / f"{path.stem}_masked{path.suffix}")

        masked_image.save(output_path)
        logger.info(f"Masked {len(regions)} regions in {path.name} → {output_path}")
        return output_path

    def _apply_blur(
        self, image: "Image.Image", regions: List[Dict[str, int]]
    ) -> "Image.Image":
        """Apply gaussian blur to specified regions."""
        for region in regions:
            box = self._region_to_box(region, image.size)
            cropped = image.crop(box)
            blurred = cropped.filter(ImageFilter.GaussianBlur(radius=self.blur_radius))
            image.paste(blurred, box[:2])
        return image

    def _apply_redaction(
        self, image: "Image.Image", regions: List[Dict[str, int]]
    ) -> "Image.Image":
        """Apply black box redaction to specified regions."""
        draw = ImageDraw.Draw(image)
        for region in regions:
            box = self._region_to_box(region, image.size)
            draw.rectangle(box, fill=self.redact_color)
        return image

    def _region_to_box(
        self, region: Dict[str, int], image_size: Tuple[int, int]
    ) -> Tuple[int, int, int, int]:
        """Convert a region dict to a PIL box tuple with padding."""
        p = self.padding
        left = max(0, region["left"] - p)
        top = max(0, region["top"] - p)
        right = min(image_size[0], region["left"] + region["width"] + p)
        bottom = min(image_size[1], region["top"] + region["height"] + p)
        return (left, top, right, bottom)

    def blur_image_bytes(
        self,
        image_bytes: bytes,
        regions: List[Dict[str, int]],
        mode: str = "blur",
    ) -> bytes:
        """Blur regions in an image from bytes, return masked image bytes."""
        import io

        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is not installed")

        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        if mode == "blur":
            masked = self._apply_blur(image, regions)
        else:
            masked = self._apply_redaction(image, regions)

        buffer = io.BytesIO()
        masked.save(buffer, format="PNG")
        return buffer.getvalue()

    def get_pii_regions(
        self,
        words_with_positions: List[Dict[str, Any]],
        detected_entities: List[Dict[str, Any]],
    ) -> List[Dict[str, int]]:
        """
        Map detected PII entities to image regions using OCR word positions.

        This cross-references the detected entity text spans with OCR word
        bounding boxes to identify which image regions contain PII.
        """
        pii_regions = []

        for entity in detected_entities:
            entity_text = entity.get("text", "").lower().split()
            for word_info in words_with_positions:
                if word_info["text"].lower() in entity_text:
                    pii_regions.append({
                        "left": word_info["left"],
                        "top": word_info["top"],
                        "width": word_info["width"],
                        "height": word_info["height"],
                    })

        # Merge overlapping regions
        pii_regions = self._merge_regions(pii_regions)
        return pii_regions

    def _merge_regions(
        self, regions: List[Dict[str, int]]
    ) -> List[Dict[str, int]]:
        """Merge overlapping bounding box regions."""
        if not regions:
            return []

        sorted_regions = sorted(regions, key=lambda r: (r["top"], r["left"]))
        merged = [sorted_regions[0]]

        for region in sorted_regions[1:]:
            last = merged[-1]
            # Check vertical overlap
            if (
                region["top"] <= last["top"] + last["height"] + self.padding
                and region["left"] <= last["left"] + last["width"] + self.padding
            ):
                # Merge
                new_left = min(last["left"], region["left"])
                new_top = min(last["top"], region["top"])
                new_right = max(
                    last["left"] + last["width"], region["left"] + region["width"]
                )
                new_bottom = max(
                    last["top"] + last["height"], region["top"] + region["height"]
                )
                merged[-1] = {
                    "left": new_left,
                    "top": new_top,
                    "width": new_right - new_left,
                    "height": new_bottom - new_top,
                }
            else:
                merged.append(region)

        return merged
