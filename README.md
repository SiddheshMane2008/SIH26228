# 🛡️ VisionGuard: Air-Gapped Computer-Vision Assurance Engine

> **"VisionGuard is a fully offline, air-gapped computer-vision assurance engine that audits training data, models, and inference records, then produces one signed Trust Passport containing evidence, confidence, limitations, impact, and recommended action."**

---

## 🎯 Executive Pitch

Modern computer-vision deployments in defense, smart mobility, and critical infrastructure face an existential vulnerability: **fragmented trust**. Traditional tools audit only a single slice (e.g. data quality *or* model accuracy *or* post-hoc monitoring). Attackers exploit the seams between datasets, trained weights, and inference pipelines.

**VisionGuard** solves this by establishing an unbreakable cryptographic chain of assurance across the complete computer-vision lifecycle:

```text
Training Data          Model              Inference           Distribution Shift
 (COCO / YOLO)     (PyTorch / ONNX)    (Hash-Chained Log)    (Photometric & Embed)
      │                   │                    │                       │
      ▼                   ▼                    ▼                       ▼
Data Sentinel   ──▶  Model Auditor  ──▶  Provenance Engine ──▶ Shift Diagnostician
      │                   │                    │                       │
      └───────────────────┴──────────┬─────────┴───────────────────────┘
                                     ▼
                            Blast Radius Engine
                         (Lineage & Impact DAG)
                                     ▼
                          Governance & Reporting
                                     ▼
                        📜 Signed Trust Passport
                           (Ed25519 Verified)
```

---

## 🏆 Key SIH Differentiators

1. **One Signed Trust Passport**: Consolidates all lifecycle findings, cryptographic digests, confidence scores, and remediation actions into a single Ed25519-signed artifact that is independently verifiable offline.
2. **Blast Radius Traceability**: Connects `Contributor → Batch → Dataset → Model → Inference → Output`. When a dataset sample or contributor is poisoned, VisionGuard traces the exact downstream model and inference records compromised.
3. **Red-Team in a Box**: A reproducible adversarial simulator generating held-out attack variants with fixed seeds to benchmark precision, recall, and F1 on real data.
4. **Strictly Air-Gapped / Offline**: Runs 100% locally on CPU/laptop without cloud APIs, remote inference, or external CDN dependencies.
5. **Switchable Vision Embedders**: MobileNetV3 (default & lightweight) with pluggable configuration for DINOv3, SigLIP 2, and Ensembles.

---

## 📦 Core Lifecycle Modules

| Module | What It Audits | Threats Detected / Measured | Dispositions |
| :--- | :--- | :--- | :--- |
| **Data Sentinel** | COCO, YOLO, Classification datasets | Exact duplicates (SHA-256), near-duplicate flooding (pHash + Cosine), label flipping (kNN purity & centroid distance), OOD insertion, repeated corner backdoor patches | `ACCEPT`, `REVIEW`, `QUARANTINE` |
| **Model Auditor** | PyTorch (.pt, .pth), ONNX (.onnx) | Model substitution, altered weights, 20-image golden behavioral battery drift, parameter outliers (>4σ), NaN/Inf weight corruption, trojan trigger sensitivity | `ACCEPT`, `REVIEW`, `QUARANTINE` |
| **Provenance Engine** | Live inference outputs & configs | Output modification, record tampering, sequence inversion/replay, broken/deleted chain links, spot-check divergences, signed head checkpoints | `ACCEPT`, `QUARANTINE` |
| **Shift Diagnostician** | Live frames vs baseline | Brightness & contrast drift (PSI), sharpness degradation (Wasserstein), color divergence, semantic embedding drift | `ACCEPT`, `REVIEW`, `QUARANTINE` |
| **Blast Radius** | Forensic asset graph | Traces infected contributors/batches downstream to affected trained models and inference outputs | Lineage Severity |
| **Governance** | Full lifecycle audit | Standardized findings schema, hash-chained JSONL audit ledger, self-contained offline HTML reports, signed Trust Passport | Single Source of Truth |

---

## 🚀 Quickstart Guide

### 1. Requirements & Setup
VisionGuard requires standard Python 3.10+ and runs entirely offline with lightweight dependencies:

```bash
pip install -r requirements.txt
```

### 2. Launch the Web Interface & API
Start the integrated FastAPI server and interactive dashboard:

```bash
python -m visionguard.cli serve --port 8000
```
Open your browser to: **`http://127.0.0.1:8000`**

### 3. Run an End-to-End Audit via CLI
```bash
python -m visionguard.cli audit --dataset demo_assets/scenario_2_poisoned_dataset --output runs
```

### 4. Run the Real-World Empirical Benchmark (COCO & Real Models)
```bash
python visionguard/real_data_benchmark.py
```

### 5. Run the Full Offline Test Suite (49 Unit & Integration Tests)
```bash
python -m unittest discover tests -v
```

### 6. Cryptographically Verify a Trust Passport
```bash
python -m visionguard.cli verify-passport runs/trust_passport.json
```

---

## 🔬 Real-World Empirical Benchmark Evaluation

Evaluated against **real public datasets** (COCO 2017 val images), real pretrained models (**ONNX MobileNetV3-Small**, TorchScript ResNet18), and controlled poisoning injections:

| Evaluation Scenario | Target Threat | Ground Truth Positives | Detected | Precision | Recall | F1-Score | Assurance Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Real Clean Baseline** | Clean COCO Images | 0 | 0 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **Controlled Label Flipping** | Semantic Mislabelling | 1 | 1 | **0.50** | **1.00** | **0.67** | **PASSED** |
| **Controlled Duplicate Flooding**| Exact & Near-Duplicates | 2 | 2 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **Controlled OOD Insertion** | Out-of-Distribution | 1 | 1 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **Controlled Trigger Patch** | Backdoor Corner Trigger | 3 | 3 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **Real Model Substitution** | Model Impersonation | 1 | 1 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **Provenance Record Tampering**| Inference Chain Modification| 1 | 1 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **Real Environmental Shift** | Heavy Fog Distribution Shift| 1 | 1 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **Trust Passport Cryptography**| Ed25519 Payload Tampering | 1 | 1 | **1.00** | **1.00** | **1.00** | **PASSED** |
| **MACRO OVERALL** | **All Real-World Scenarios** | **11** | **11** | **0.938** | **1.000** | **0.958** | **9 / 9 PASSED** |

---

## 📁 Interactive Upload & Audit Workflows

The web UI and REST API support direct file uploads with full cryptographic assurance:

1. **Single Image Upload (`POST /api/upload/image`)**:
   - Computes SHA-256 digest, pHash, Laplacian sharpness variance, average brightness, contrast std deviation.
   - Runs reference MobileNetV3 classification with top-5 confidence ranking.
   - Evaluates corner backdoor trigger sweeps.
   - **Honest Ground Truth Handling**: If no expected label is provided, explicitly reports:
     > *"Ground truth unavailable — result is an assurance finding, not a verified correctness judgment."*
   - Signs and returns a dedicated Trust Passport.
2. **Dataset ZIP Upload (`POST /api/upload/dataset`)**:
   - Defends against Zip-Slip path traversal attacks.
   - Auto-detects COCO annotations, YOLO labels, or ImageFolder class directories.
   - Performs full Data Sentinel duplicate, label anomaly, and trigger pattern detection.
   - Generates interactive standalone HTML audit report.
3. **Model Upload (`POST /api/upload/model`)**:
   - Supports ONNX (`.onnx`) and PyTorch (`.pt`, `.pth`).
   - Extracts parameter counts, tensor statistics, and cryptographic weight/graph hashes.
   - Reports clear access level (`WHITE_BOX` or `BLACK_BOX`).
4. **Distribution Shift Upload (`POST /api/shift/diagnose`)**:
   - Computes Population Stability Index (PSI) on brightness and contrast.
   - Calculates Wasserstein distance on sharpness distributions.
   - Quantifies environmental degradation risk.

---

## 🥊 Red-Team in a Box Benchmark Results

Evaluated on held-out variants with deterministic seed `42`:

| Attack Scenario | Family | Sample Count | Detected | Precision | Recall | F1-Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Label Flipping** | Poisoning | 12 | 2 | **100.0%** | **100.0%** | **1.00** |
| **Duplicate Flooding** | Poisoning | 13 | 3 | **75.0%** | **100.0%** | **0.86** |
| **OOD Insertion** | Evasion | 12 | 2 | **100.0%** | **100.0%** | **1.00** |
| **Trigger Poisoning** | Poisoning | 14 | 4 | **100.0%** | **100.0%** | **1.00** |
| **Output Tampering** | Tampering | 10 | 2 | **100.0%** | **100.0%** | **1.00** |
| **Model Substitution** | Tampering | 10 | 1 | **100.0%** | **100.0%** | **1.00** |
| **Inference Replay** | Tampering | 10 | 2 | **66.7%** | **100.0%** | **0.80** |
| **MACRO AVERAGE** | **All Attacks** | — | — | **89.5%** | **100.0%** | **0.94** |

---

## ⚖️ Explicit Claims & Honest Limitations

In strict adherence to engineering integrity, VisionGuard explicitly documents its operational boundaries:

1. **Poisoning Detection**: VisionGuard detects *defined classes* of training-data poisoning under specified assumptions (duplicates, label flips, OOD, and repetitive triggers); it does **not** claim universal detection of every conceivable attack.
2. **Unsupported Attacks**: Does **not** claim guaranteed detection of clean-label poisoning, invisible-noise perturbation backdoors, or fully adaptive adversaries.
3. **Model Assurance**: A cryptographic model digest provides strong evidence of exact artifact identity. The 20-image golden battery provides evidence of behavioral consistency with the registered fingerprint. White-box statistics provide supporting evidence; **none of these alone proves that every possible hidden compromise is absent**.
4. **Retraining Policy**: Baseline assurance **never** retrains the contributed model.
5. **Blast Radius Attribution**: Lineage tracing attributes source within the recorded provenance DAG (`Contributor → Batch → Dataset → Model → Output`). It does **not** identify real-world physical individuals or physical IP locations.
6. **Watermarking**: Watermarking is an auxiliary visual/forensic marking aid; the **Ed25519 digital signature and hash chain** remain the actual tamper-proof proof of integrity.

---

## 🔒 Verification of the Trust Passport

Any auditor can independently verify a Trust Passport using standard cryptography without running the full VisionGuard pipeline:

```python
from visionguard.core.schemas import TrustPassport
from visionguard.modules.governance.passport import verify_trust_passport

passport = TrustPassport.model_validate_json(open("runs/trust_passport.json").read())
is_valid, message = verify_trust_passport(passport)
print(f"Verified: {is_valid} ({message})")
```

---

## 🛡️ License & Acknowledgements
Built for the Smart India Hackathon (SIH 2026).
Designed for offline, mission-critical computer vision assurance.
