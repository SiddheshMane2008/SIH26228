"""
Red-Team in a Box: Attack Scenario Simulator for VisionGuard

Generates reproducible, deterministic adversarial scenarios with fixed seeds:
1. Label Flipping
2. Duplicate Flooding (exact byte & visual near-duplicate)
3. Out-Of-Distribution (OOD) Insertion
4. Trigger / Backdoor Patch Poisoning
5. Model Substitution / Weight Alteration
6. Inference Record Tampering
7. Replay & Sequence Inversion
8. Distribution Shift (photometric plunge & blur)
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter
import torch
import torch.nn as nn

from visionguard.core.crypto import KeyPair
from visionguard.modules.provenance.chain import InferenceChain


class RedTeamSimulator:
    """Generates synthetic adversarial test assets with mathematical determinism."""

    def __init__(self, seed: int = 42):
        self.seed = seed

    def _draw_object(self, img: Image.Image, shape: str, color: tuple, offset: int = 0):
        draw = ImageDraw.Draw(img)
        if shape == "rect":
            draw.rectangle([16 + offset, 16 + offset, 48 + offset, 48 + offset], fill=color)
        elif shape == "circle":
            draw.ellipse([16 + offset, 16 + offset, 48 + offset, 48 + offset], fill=color)
        elif shape == "triangle":
            draw.polygon([(32, 12), (12, 52), (52, 52)], fill=color)

    def generate_poisoned_dataset(
        self,
        output_dir: Path,
        attack_type: str = "label_flip",
        num_clean: int = 10,
        num_poisoned: int = 2
    ) -> Dict[str, Any]:
        """
        Creates a self-contained dataset with known clean and poisoned ground truth indices.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        class_a = output_dir / "class_a"
        class_b = output_dir / "class_b"
        class_a.mkdir(exist_ok=True)
        class_b.mkdir(exist_ok=True)

        ground_truth: Dict[str, bool] = {}  # sample_id -> is_attack

        # 1. Base clean samples
        for i in range(num_clean // 2):
            # Class A: red rectangles
            np.random.seed(self.seed + i)
            bg = np.random.randint(30, 70, size=(64, 64, 3), dtype=np.uint8)
            img_a = Image.fromarray(bg)
            self._draw_object(img_a, "rect", (210, 30 + i * 5, 30), offset=i % 4)
            path_a = class_a / f"clean_a_{i}.png"
            img_a.save(path_a)
            ground_truth[f"class_a_{path_a.stem}"] = False

            # Class B: blue circles
            bg = np.random.randint(30, 70, size=(64, 64, 3), dtype=np.uint8)
            img_b = Image.fromarray(bg)
            self._draw_object(img_b, "circle", (30, 40 + i * 5, 210), offset=i % 4)
            path_b = class_b / f"clean_b_{i}.png"
            img_b.save(path_b)
            ground_truth[f"class_b_{path_b.stem}"] = False

        # 2. Inject specified attack
        if attack_type == "label_flip":
            # Place red rectangles into class_b
            for j in range(num_poisoned):
                img = Image.new("RGB", (64, 64), color=(50, 50, 50))
                self._draw_object(img, "rect", (215, 25, 25))
                path = class_b / f"poison_flip_{j}.png"
                img.save(path)
                ground_truth[f"class_b_{path.stem}"] = True

        elif attack_type == "duplicate_flood":
            # Exact duplicate copies
            src_path = class_a / "clean_a_0.png"
            for j in range(num_poisoned):
                dup_path = class_a / f"dup_flood_{j}.png"
                with open(src_path, "rb") as sf, open(dup_path, "wb") as df:
                    df.write(sf.read())
                ground_truth[f"class_a_{dup_path.stem}"] = True

        elif attack_type == "ood_insertion":
            # Insert extreme static noise images
            for j in range(num_poisoned):
                np.random.seed(self.seed + 999 + j)
                noise_arr = np.random.randint(0, 255, size=(64, 64, 3), dtype=np.uint8)
                ood_path = class_a / f"poison_ood_{j}.png"
                Image.fromarray(noise_arr).save(ood_path)
                ground_truth[f"class_a_{ood_path.stem}"] = True

        elif attack_type == "trigger_poisoning":
            # Add yellow checkerboard patch to bottom-right corner of class_a samples
            for j in range(num_poisoned + 2):  # Need at least 3 co-occurrences
                img = Image.new("RGB", (64, 64), color=(40, 40, 40))
                self._draw_object(img, "rect", (150, 100, 50))
                draw = ImageDraw.Draw(img)
                for tx in range(56, 64):
                    for ty in range(56, 64):
                        c = (255, 255, 0) if (tx + ty) % 2 == 0 else (0, 0, 0)
                        draw.point((tx, ty), fill=c)
                trig_path = class_a / f"poison_trigger_{j}.png"
                img.save(trig_path)
                ground_truth[f"class_a_{trig_path.stem}"] = True

        return {
            "dataset_dir": output_dir,
            "attack_type": attack_type,
            "ground_truth": ground_truth
        }

    def generate_tampered_chain(self, attack_type: str = "output_modification") -> Tuple[InferenceChain, List[int]]:
        """Generates an inference chain with known injected tamper indices."""
        chain = InferenceChain(chain_id="REDTEAM-CHAIN")
        model_digest = "b" * 64

        for i in range(10):
            chain.append_record(
                input_data=f"redteam_input_{i}",
                model_digest=model_digest,
                output={"label": f"vehicle_{i}", "confidence": 0.90}
            )

        tampered_indices = []

        if attack_type == "output_modification":
            # Tamper output of record 3 and 7
            tampered_indices = [3, 7]
            for idx in tampered_indices:
                chain.records[idx].output = {"label": "MALICIOUS_OVERRIDE", "confidence": 0.999}

        elif attack_type == "model_substitution":
            # Substitute model digest in record 4
            tampered_indices = [4]
            chain.records[4].model_digest = "deadbeef" * 8

        elif attack_type == "replay":
            # Swap records 2 and 3
            tampered_indices = [2, 3]
            chain.records[2], chain.records[3] = chain.records[3], chain.records[2]

        return chain, tampered_indices
