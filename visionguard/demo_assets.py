"""
Demo Assets Generator for VisionGuard

Generates offline, ready-to-run demo scenarios for hackathon presentations, judging, and video recording:
- Scenario 1: Clean Training Data
- Scenario 2: Poisoned Training Data (Duplicates, Label Flips, Triggers)
- Scenario 3: Model Integrity & Substitution Test Models
- Scenario 4: Cryptographic Inference Chain (Clean vs Tampered)
- Scenario 5: Distribution Shift (Normal vs Foggy / Low-Light)
"""

from pathlib import Path
from typing import Dict, Any
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter
import numpy as np
import torch
import torch.nn as nn

from visionguard.core.crypto import KeyPair
from visionguard.modules.provenance.chain import InferenceChain


class LightweightCVModel(nn.Module):
    """Clean lightweight classification model for demo."""
    def __init__(self, num_classes=5):
        super().__init__()
        self.conv1 = nn.Conv2d(3, 16, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm2d(16)
        self.relu = nn.ReLU()
        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc = nn.Linear(16, num_classes)

    def forward(self, x):
        x = self.relu(self.bn1(self.conv1(x)))
        x = self.pool(x)
        x = torch.flatten(x, 1)
        return self.fc(x)


def create_demo_assets(base_dir: Path) -> Dict[str, Any]:
    """Generates all standard demo scenarios into base_dir."""
    base_dir.mkdir(parents=True, exist_ok=True)
    paths = {}

    # ==========================================
    # 1. Scenario 1: Clean Dataset
    # ==========================================
    clean_ds_dir = base_dir / "scenario_1_clean_dataset"
    class_stop = clean_ds_dir / "stop_signs"
    class_yield = clean_ds_dir / "yield_signs"
    class_stop.mkdir(parents=True, exist_ok=True)
    class_yield.mkdir(parents=True, exist_ok=True)

    for i in range(6):
        np.random.seed(100 + i * 17)
        # Stop signs: varying scale, position, color nuance, background
        bg_val = 30 + (i * 23) % 70
        img = Image.new("RGB", (128, 128), color=(bg_val, bg_val + 5, bg_val + 10))
        draw = ImageDraw.Draw(img)
        cx, cy = 64 + ((i % 3) - 1) * 8, 64 + ((i // 2) - 1) * 6
        rad = 30 + (i % 3) * 6
        r_col = 195 + (i * 11) % 55
        draw.rectangle([cx - rad, cy - rad, cx + rad, cy + rad], fill=(r_col, 25 + (i * 7) % 30, 25))
        draw.text((cx - 16, cy - 6), "STOP", fill=(255, 255, 255))
        img.save(class_stop / f"stop_{i}.png")

        # Yield signs: varying vertices, positions, colors
        bg2_val = 40 + (i * 19) % 65
        img2 = Image.new("RGB", (128, 128), color=(bg2_val + 10, bg2_val, bg2_val + 5))
        draw2 = ImageDraw.Draw(img2)
        ox, oy = ((i % 3) - 1) * 7, ((i // 2) - 1) * 5
        s = 0.85 + (i % 3) * 0.15
        p1 = (int(64 + ox), int(108 * s + oy))
        p2 = (int(16 * s + ox), int(26 + oy))
        p3 = (int(112 * s + ox), int(26 + oy))
        y_col = 210 + (i * 9) % 40
        draw2.polygon([p1, p2, p3], fill=(y_col, 185 + (i * 8) % 40, 20))
        draw2.text((int(42 + ox), int(38 + oy)), "YIELD", fill=(0, 0, 0))
        img2.save(class_yield / f"yield_{i}.png")

    paths["clean_dataset"] = clean_ds_dir

    # ==========================================
    # 2. Scenario 2: Poisoned Dataset
    # ==========================================
    poison_ds_dir = base_dir / "scenario_2_poisoned_dataset"
    p_stop = poison_ds_dir / "stop_signs"
    p_yield = poison_ds_dir / "yield_signs"
    p_stop.mkdir(parents=True, exist_ok=True)
    p_yield.mkdir(parents=True, exist_ok=True)

    # Copy clean samples
    for f in class_stop.iterdir():
        Image.open(f).save(p_stop / f.name)
    for f in class_yield.iterdir():
        Image.open(f).save(p_yield / f.name)

    # Injected Threat A: Exact Duplicate
    orig_f = p_stop / "stop_0.png"
    Image.open(orig_f).save(p_stop / "stop_0_exact_dup.png")

    # Injected Threat B: Label Flip (Red Stop sign labeled as Yield sign)
    flipped_img = Image.new("RGB", (128, 128), color=(50, 50, 50))
    draw_f = ImageDraw.Draw(flipped_img)
    draw_f.rectangle([28, 28, 100, 100], fill=(215, 25, 25))
    draw_f.text((44, 58), "STOP", fill=(255, 255, 255))
    flipped_img.save(p_yield / "malicious_label_flip.png")

    # Injected Threat C: Trojan / Backdoor Triggers (Yellow checkerboard patch on 3 stop signs)
    for t_idx in range(3):
        trig_img = Image.open(p_stop / f"stop_{t_idx + 1}.png").copy()
        draw_t = ImageDraw.Draw(trig_img)
        for tx in range(112, 128):
            for ty in range(112, 128):
                c = (255, 255, 0) if (tx + ty) % 2 == 0 else (0, 0, 0)
                draw_t.point((tx, ty), fill=c)
        trig_img.save(p_stop / f"stop_trigger_backdoor_{t_idx}.png")

    paths["poisoned_dataset"] = poison_ds_dir

    # ==========================================
    # 3. Scenario 3: Models (Clean & Substituted)
    # ==========================================
    models_dir = base_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(42)
    clean_model = LightweightCVModel(num_classes=5)
    clean_model_path = models_dir / "registered_traffic_model.pt"
    torch.save(clean_model, clean_model_path)
    paths["clean_model"] = clean_model_path

    # Substituted Model (different weights seed)
    torch.manual_seed(999)
    sub_model = LightweightCVModel(num_classes=5)
    sub_model_path = models_dir / "substituted_traffic_model.pt"
    torch.save(sub_model, sub_model_path)
    paths["substituted_model"] = sub_model_path

    # ==========================================
    # 4. Scenario 4: Inference Chains
    # ==========================================
    kp = KeyPair.generate()
    clean_chain = InferenceChain("PROV-DEMO-01", keypair=kp)
    for i in range(5):
        clean_chain.append_record(
            input_data=f"traffic_camera_frame_{i:04d}.jpg",
            model_digest="d8e8fca9" * 8,
            output={"detected_sign": "STOP", "confidence": 0.98}
        )
    clean_cp = clean_chain.create_head_checkpoint()
    paths["clean_chain"] = clean_chain
    paths["clean_checkpoint"] = clean_cp

    # Tampered Chain (Record 2 modified)
    tampered_chain = InferenceChain("PROV-DEMO-01", keypair=kp)
    tampered_chain.records = [r.model_copy(deep=True) for r in clean_chain.records]
    tampered_chain.records[2].output = {"detected_sign": "SPEED_LIMIT_100", "confidence": 0.999}
    paths["tampered_chain"] = tampered_chain

    # ==========================================
    # 5. Scenario 5: Distribution Shift
    # ==========================================
    shift_dir = base_dir / "scenario_5_distribution_shift"
    base_shift_dir = shift_dir / "baseline_daylight"
    eval_shift_dir = shift_dir / "live_heavy_fog"
    base_shift_dir.mkdir(parents=True, exist_ok=True)
    eval_shift_dir.mkdir(parents=True, exist_ok=True)

    for i in range(8):
        # Baseline daylight
        day_img = Image.new("RGB", (128, 128), color=(180, 200, 220))
        d_draw = ImageDraw.Draw(day_img)
        d_draw.rectangle([20, 40, 108, 110], fill=(60, 60, 60))
        day_img.save(base_shift_dir / f"day_{i}.png")

        # Heavy fog & contrast loss
        fog_img = day_img.filter(ImageFilter.GaussianBlur(radius=3))
        enhancer = ImageEnhance.Contrast(fog_img)
        fog_img = enhancer.enhance(0.3)
        fog_img.save(eval_shift_dir / f"fog_{i}.png")

    paths["shift_baseline"] = base_shift_dir
    paths["shift_live"] = eval_shift_dir

    return paths
