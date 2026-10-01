"""
Dataset Parsers for Data Sentinel

Supports:
- COCO format (instances.json with images, annotations, categories)
- YOLO format (images/ directory + labels/ directory with normalized bounding boxes)
- Classification format (Class subfolders or metadata.json)
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from PIL import Image

from visionguard.core.exceptions import DatasetIntegrityError


@dataclass
class DatasetSample:
    """Standardized representation of a single dataset sample."""
    sample_id: str
    image_path: Path
    labels: List[int]
    label_names: List[str]
    bounding_boxes: List[List[float]] = field(default_factory=list)  # [[x, y, w, h], ...]
    contributor_id: str = "contributor_unknown"
    batch_id: str = "batch_001"
    metadata: Dict[str, Any] = field(default_factory=dict)


class DatasetParser:
    """Parses COCO, YOLO, and Classification dataset directories."""

    @staticmethod
    def parse_coco(annotation_file: Path, images_dir: Path) -> List[DatasetSample]:
        if not annotation_file.is_file():
            raise DatasetIntegrityError(f"COCO annotation file not found: {annotation_file}")
        if not images_dir.is_dir():
            raise DatasetIntegrityError(f"COCO images directory not found: {images_dir}")

        with open(annotation_file, "r", encoding="utf-8") as f:
            coco_data = json.load(f)

        categories = {c["id"]: c.get("name", str(c["id"])) for c in coco_data.get("categories", [])}
        
        # Map image_id to annotations
        img_annos: Dict[int, List[Dict[str, Any]]] = {}
        for ann in coco_data.get("annotations", []):
            img_id = ann["image_id"]
            img_annos.setdefault(img_id, []).append(ann)

        samples: List[DatasetSample] = []
        for img_info in coco_data.get("images", []):
            img_id = img_info["id"]
            file_name = img_info["file_name"]
            img_path = images_dir / file_name
            if not img_path.is_file():
                # Check directly in parent dir if not found in images_dir
                img_path = images_dir.parent / file_name
                if not img_path.is_file():
                    continue

            annos = img_annos.get(img_id, [])
            labels = [a["category_id"] for a in annos]
            label_names = [categories.get(cid, str(cid)) for cid in labels]
            bboxes = [a.get("bbox", []) for a in annos]
            
            contributor = img_info.get("contributor_id", "contributor_default")
            batch = img_info.get("batch_id", "batch_default")

            samples.append(DatasetSample(
                sample_id=str(img_id),
                image_path=img_path,
                labels=labels if labels else [0],
                label_names=label_names if label_names else ["unlabeled"],
                bounding_boxes=bboxes,
                contributor_id=contributor,
                batch_id=batch,
                metadata=img_info
            ))
        return samples

    @staticmethod
    def parse_yolo(yolo_dir: Path) -> List[DatasetSample]:
        if not yolo_dir.is_dir():
            raise DatasetIntegrityError(f"YOLO directory not found: {yolo_dir}")

        images_dir = yolo_dir / "images"
        labels_dir = yolo_dir / "labels"
        
        # Support flat layout if images/ doesn't exist
        if not images_dir.exists():
            images_dir = yolo_dir
            labels_dir = yolo_dir

        valid_exts = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
        image_files = [f for f in images_dir.iterdir() if f.suffix.lower() in valid_exts]

        samples: List[DatasetSample] = []
        for img_path in sorted(image_files):
            stem = img_path.stem
            label_file = labels_dir / f"{stem}.txt"
            
            labels = []
            bboxes = []
            if label_file.is_file():
                with open(label_file, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            cls_id = int(parts[0])
                            bbox = [float(x) for x in parts[1:5]]
                            labels.append(cls_id)
                            bboxes.append(bbox)

            # Check if metadata file exists (e.g. meta.json or sidecar)
            meta_file = labels_dir / f"{stem}.meta.json"
            contributor = "contributor_default"
            batch = "batch_default"
            if meta_file.is_file():
                try:
                    with open(meta_file, "r") as mf:
                        mdata = json.load(mf)
                        contributor = mdata.get("contributor_id", contributor)
                        batch = mdata.get("batch_id", batch)
                except Exception:
                    pass

            samples.append(DatasetSample(
                sample_id=stem,
                image_path=img_path,
                labels=labels if labels else [0],
                label_names=[f"class_{c}" for c in labels] if labels else ["class_0"],
                bounding_boxes=bboxes,
                contributor_id=contributor,
                batch_id=batch
            ))
        return samples

    @staticmethod
    def parse_zip(zip_path: Path, extract_base_dir: Optional[Path] = None) -> tuple[List[DatasetSample], str]:
        import zipfile
        if not zip_path.is_file():
            raise DatasetIntegrityError(f"ZIP file not found: {zip_path}")
        if not zipfile.is_zipfile(zip_path):
            raise DatasetIntegrityError(f"File is not a valid ZIP archive: {zip_path.name}")

        extract_dir = (extract_base_dir or zip_path.parent) / f"extracted_{zip_path.stem}"
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Security check: prevent zip slip / directory traversal attacks
                for member in zf.infolist():
                    target_path = (extract_dir / member.filename).resolve()
                    if not str(target_path).startswith(str(extract_dir.resolve())):
                        raise DatasetIntegrityError(f"Security violation in ZIP: malicious relative path '{member.filename}'")
                zf.extractall(extract_dir)
        except zipfile.BadZipFile as e:
            raise DatasetIntegrityError(f"Corrupt or malformed ZIP archive: {str(e)}")

        # Check if archive was empty
        extracted_files = [f for f in extract_dir.rglob("*") if f.is_file()]
        if not extracted_files:
            raise DatasetIntegrityError("Empty ZIP archive: no files extracted.")

        # Detect format inside extracted directory
        # 1. COCO: search for instances*.json or *.json with images and annotations
        json_candidates = list(extract_dir.rglob("*.json"))
        for jf in json_candidates:
            try:
                with open(jf, "r", encoding="utf-8") as f:
                    cdata = json.load(f)
                    if isinstance(cdata, dict) and "images" in cdata and "annotations" in cdata:
                        img_dir = jf.parent / "images" if (jf.parent / "images").is_dir() else jf.parent
                        return DatasetParser.parse_coco(jf, img_dir), "coco"
            except Exception:
                continue

        # 2. YOLO: search for labels/ and images/
        label_dirs = [d for d in extract_dir.rglob("labels") if d.is_dir()]
        if label_dirs:
            yolo_root = label_dirs[0].parent
            return DatasetParser.parse_yolo(yolo_root), "yolo"

        # 3. Classification: subfolders with images
        for root, dirs, _ in os.walk(extract_dir):
            if dirs:
                sub_has_images = any(
                    any(f.suffix.lower() in {".jpg", ".jpeg", ".png", ".bmp", ".webp"} for f in Path(root, d).iterdir() if f.is_file())
                    for d in dirs if Path(root, d).is_dir()
                )
                if sub_has_images:
                    return DatasetParser.parse_classification(Path(root)), "classification"

        # Fallback to general classification parser on extract_dir
        return DatasetParser.parse_classification(extract_dir), "classification"

    @staticmethod
    def parse_classification(data_dir: Path) -> List[DatasetSample]:
        if not data_dir.is_dir():
            raise DatasetIntegrityError(f"Classification directory not found: {data_dir}")

        subdirs = [d for d in data_dir.iterdir() if d.is_dir()]
        samples: List[DatasetSample] = []
        valid_exts = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}

        if subdirs:
            # Subfolder-per-class layout (ImageFolder)
            for cls_idx, cls_dir in enumerate(sorted(subdirs)):
                cls_name = cls_dir.name
                for img_file in sorted(cls_dir.iterdir()):
                    if img_file.suffix.lower() in valid_exts and img_file.is_file():
                        # Pre-check image file integrity
                        is_corrupt = False
                        err_msg = ""
                        try:
                            with Image.open(img_file) as im:
                                im.verify()
                        except Exception as e:
                            is_corrupt = True
                            err_msg = str(e)

                        if is_corrupt:
                            samples.append(DatasetSample(
                                sample_id=f"CORRUPT_{img_file.stem}",
                                image_path=img_file,
                                labels=[-1],
                                label_names=["corrupt_unreadable"],
                                metadata={"is_corrupted": True, "error": err_msg},
                                contributor_id="contributor_default",
                                batch_id="batch_default"
                            ))
                        else:
                            samples.append(DatasetSample(
                                sample_id=f"{cls_name}_{img_file.stem}",
                                image_path=img_file,
                                labels=[cls_idx],
                                label_names=[cls_name],
                                contributor_id="contributor_default",
                                batch_id="batch_default"
                            ))
        else:
            # Flat directory
            for img_file in sorted(data_dir.iterdir()):
                if img_file.suffix.lower() in valid_exts and img_file.is_file():
                    is_corrupt = False
                    err_msg = ""
                    try:
                        with Image.open(img_file) as im:
                            im.verify()
                    except Exception as e:
                        is_corrupt = True
                        err_msg = str(e)

                    if is_corrupt:
                        samples.append(DatasetSample(
                            sample_id=f"CORRUPT_{img_file.stem}",
                            image_path=img_file,
                            labels=[-1],
                            label_names=["corrupt_unreadable"],
                            metadata={"is_corrupted": True, "error": err_msg},
                            contributor_id="contributor_default",
                            batch_id="batch_default"
                        ))
                    else:
                        samples.append(DatasetSample(
                            sample_id=img_file.stem,
                            image_path=img_file,
                            labels=[0],
                            label_names=["class_0"],
                            contributor_id="contributor_default",
                            batch_id="batch_default"
                        ))
        return samples
