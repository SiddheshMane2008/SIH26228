"""
Data Sentinel Integrity Detectors

Implements defined threat detection:
1. Exact and near-duplicate flooding (SHA-256, pHash, visual embeddings)
2. Label flipping and systematic mislabeling (embedding kNN consistency & centroid distance)
3. Out-Of-Distribution (OOD) insertion (embedding distance distribution)
4. Repeated trigger / patch patterns (localized patch hash repetition)
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np
from PIL import Image

from visionguard.core.crypto import (
    compute_phash,
    phash_hamming_distance,
    sha256_file,
    sha256_text
)
from visionguard.core.schemas import (
    DispositionEnum,
    Finding,
    ModuleEnum,
    SeverityEnum
)
from visionguard.embedders.base import BaseEmbedder
from visionguard.modules.data_sentinel.parser import DatasetSample


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DuplicateDetector:
    """Detects exact byte duplicates and visual near-duplicates."""

    def __init__(
        self,
        phash_threshold: int = 5,
        cosine_threshold: float = 0.98
    ):
        self.phash_threshold = phash_threshold
        self.cosine_threshold = cosine_threshold

    def audit(
        self,
        samples: List[DatasetSample],
        embeddings: np.ndarray
    ) -> Tuple[List[Finding], int, int]:
        findings: List[Finding] = []
        n = len(samples)
        exact_dups = 0
        near_dups = 0

        # 1. Exact SHA-256 duplicate detection
        sha_map: Dict[str, List[int]] = {}
        for idx, s in enumerate(samples):
            h = sha256_file(s.image_path)
            sha_map.setdefault(h, []).append(idx)

        exact_duplicate_indices: Set[int] = set()
        for h, indices in sha_map.items():
            if len(indices) > 1:
                exact_dups += (len(indices) - 1)
                primary = indices[0]
                for dup_idx in indices[1:]:
                    exact_duplicate_indices.add(dup_idx)
                    findings.append(Finding(
                        finding_id=f"FIND-DS-EXACT-DUP-{dup_idx:04d}",
                        module=ModuleEnum.DATA_SENTINEL,
                        asset=samples[dup_idx].sample_id,
                        reason="Exact byte duplicate image detected in dataset",
                        evidence={
                            "sha256": h,
                            "original_sample_id": samples[primary].sample_id,
                            "duplicate_count": len(indices),
                            "contributor_id": samples[dup_idx].contributor_id,
                            "batch_id": samples[dup_idx].batch_id
                        },
                        severity=SeverityEnum.HIGH,
                        confidence=1.0,
                        disposition=DispositionEnum.QUARANTINE,
                        recommended_action="Remove duplicate sample from training split to prevent overfitting or poison amplification.",
                        timestamp=_now_iso()
                    ))

        # 2. Perceptual Hash (pHash) and Embedding Near-Duplicate Detection
        phashes = [compute_phash(s.image_path) for s in samples]

        for i in range(n):
            if i in exact_duplicate_indices:
                continue
            for j in range(i + 1, n):
                if j in exact_duplicate_indices:
                    continue

                pdist = phash_hamming_distance(phashes[i], phashes[j])
                cos_sim = float(np.dot(embeddings[i], embeddings[j]))
                # Multi-signal near-duplicate: requires both perceptual hash AND embedding cosine agreement
                is_near_dup = (pdist <= self.phash_threshold) and (cos_sim >= self.cosine_threshold)
                if is_near_dup:
                    near_dups += 1
                    findings.append(Finding(
                        finding_id=f"FIND-DS-NEAR-DUP-{j:04d}",
                        module=ModuleEnum.DATA_SENTINEL,
                        asset=samples[j].sample_id,
                        reason="Visual near-duplicate detected (high perceptual and semantic similarity)",
                        evidence={
                            "matched_with_sample_id": samples[i].sample_id,
                            "phash_hamming_distance": pdist,
                            "embedding_cosine_similarity": round(cos_sim, 4),
                            "contributor_id": samples[j].contributor_id,
                            "batch_id": samples[j].batch_id
                        },
                        severity=SeverityEnum.MEDIUM,
                        confidence=round(min(1.0, 0.5 + (cos_sim - 0.90) * 5), 2),
                        disposition=DispositionEnum.REVIEW,
                        recommended_action="Inspect pair for data leakage, augmented copy flooding, or label conflict.",
                        timestamp=_now_iso()
                    ))

        return findings, exact_dups, near_dups


class LabelAnomalyDetector:
    """Detects label flipping and systematic mislabeling using embedding neighborhood purity."""

    def __init__(self, k_neighbors: int = 5, confidence_threshold: float = 0.65):
        self.k_neighbors = k_neighbors
        self.confidence_threshold = confidence_threshold

    def audit(
        self,
        samples: List[DatasetSample],
        embeddings: np.ndarray
    ) -> Tuple[List[Finding], int]:
        findings: List[Finding] = []
        n = len(samples)
        if n < self.k_neighbors + 1:
            return findings, 0

        # Primary label for each sample
        labels = [s.labels[0] if s.labels else 0 for s in samples]
        label_set = set(labels)
        if len(label_set) < 2:
            # Single class dataset cannot have cross-class label flips
            return findings, 0

        # Compute cosine similarity matrix
        sim_matrix = np.dot(embeddings, embeddings.T)
        # Disallow self-similarity
        np.fill_diagonal(sim_matrix, -1.0)
        # Compute class centroids
        class_centroids: Dict[int, np.ndarray] = {}
        for l in label_set:
            l_indices = [idx for idx, s_l in enumerate(labels) if s_l == l]
            if l_indices:
                class_centroids[l] = np.mean(embeddings[l_indices], axis=0)

        # Dynamic k based on dataset size
        effective_k = min(self.k_neighbors, max(3, (n // len(label_set)) - 1)) if n >= 6 else 2

        anomaly_count = 0
        for i in range(n):
            current_label = labels[i]
            # Find k nearest neighbors in embedding space
            top_k_indices = np.argsort(sim_matrix[i])[-(effective_k):][::-1]
            neighbor_labels = [labels[idx] for idx in top_k_indices]

            # Count frequency of current label among neighbors
            matching_count = sum(1 for nl in neighbor_labels if nl == current_label)
            purity = matching_count / effective_k

            # Most common neighbor label
            most_common_label, count = Counter(neighbor_labels).most_common(1)[0]
            dominant_ratio = count / effective_k

            # Check centroid distances (using leave-one-out for own class centroid to avoid self-bias)
            own_indices = [idx for idx, l in enumerate(labels) if l == current_label and idx != i]
            other_indices = [idx for idx, l in enumerate(labels) if l == most_common_label]
            is_closer_to_other_class = False
            if own_indices and other_indices:
                c_own = np.mean(embeddings[own_indices], axis=0)
                c_oth = np.mean(embeddings[other_indices], axis=0)
                norm_own = np.linalg.norm(c_own)
                norm_oth = np.linalg.norm(c_oth)
                if norm_own > 1e-12 and norm_oth > 1e-12:
                    dist_own = 1.0 - float(np.dot(embeddings[i], c_own / norm_own))
                    dist_other = 1.0 - float(np.dot(embeddings[i], c_oth / norm_oth))
                    is_closer_to_other_class = dist_other < dist_own
            else:
                own_c = class_centroids.get(current_label)
                other_c = class_centroids.get(most_common_label)
                if own_c is not None and other_c is not None:
                    dist_own = 1.0 - float(np.dot(embeddings[i], own_c) / (np.linalg.norm(own_c) + 1e-12))
                    dist_other = 1.0 - float(np.dot(embeddings[i], other_c) / (np.linalg.norm(other_c) + 1e-12))
                    is_closer_to_other_class = dist_other < dist_own

            if purity <= 0.40 and most_common_label != current_label and dominant_ratio >= 0.60 and is_closer_to_other_class:
                # Semantic neighbors and centroid distance both indicate misplaced label
                anomaly_count += 1
                conf = round(min(0.98, max(dominant_ratio, 0.75)), 2)
                findings.append(Finding(
                    finding_id=f"FIND-DS-LABEL-FLIP-{i:04d}",
                    module=ModuleEnum.DATA_SENTINEL,
                    asset=samples[i].sample_id,
                    reason=f"Systematic mislabeling / label flip detected: assigned class {current_label} ('{samples[i].label_names[0]}'), but {int(dominant_ratio*100)}% of semantic neighbors belong to class {most_common_label}",
                    evidence={
                        "assigned_label": current_label,
                        "dominant_neighbor_label": most_common_label,
                        "neighborhood_purity": purity,
                        "nearest_neighbor_sample_ids": [samples[idx].sample_id for idx in top_k_indices],
                        "contributor_id": samples[i].contributor_id,
                        "batch_id": samples[i].batch_id
                    },
                    severity=SeverityEnum.HIGH,
                    confidence=conf,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action=f"Re-annotate or verify ground truth. Possible target for label poisoning or transcription error.",
                    timestamp=_now_iso()
                ))

        return findings, anomaly_count


class OODDetector:
    """Detects Out-Of-Distribution (OOD) insertion via distance to embedding distribution."""

    def __init__(self, percentile_cutoff: float = 95.0):
        self.percentile_cutoff = percentile_cutoff

    def audit(
        self,
        samples: List[DatasetSample],
        embeddings: np.ndarray
    ) -> Tuple[List[Finding], int]:
        findings: List[Finding] = []
        n = len(samples)
        if n < 5:
            return findings, 0

        # Compute centroid of dataset in embedding space
        centroid = np.mean(embeddings, axis=0)
        norm_centroid = centroid / (np.linalg.norm(centroid) + 1e-12)

        # Distances to centroid (1 - cosine_similarity)
        cosine_sims = np.dot(embeddings, norm_centroid)
        distances = 1.0 - cosine_sims

        cutoff = np.percentile(distances, self.percentile_cutoff)
        mean_dist = np.mean(distances)
        std_dist = np.std(distances) + 1e-8

        ood_count = 0
        for i in range(n):
            dist = distances[i]
            z_score = (dist - mean_dist) / std_dist

            # Flag if truly OOD: significant z-score AND substantial distance away from centroid
            # In embedding space, cosine distance < 0.25 is tightly bound in-distribution
            is_ood = (z_score >= 2.2 and dist >= 0.25) or (z_score >= 2.0 and dist > cutoff and dist >= 0.30)
            if is_ood:
                ood_count += 1
                findings.append(Finding(
                    finding_id=f"FIND-DS-OOD-{i:04d}",
                    module=ModuleEnum.DATA_SENTINEL,
                    asset=samples[i].sample_id,
                    reason=f"Out-of-Distribution (OOD) insertion detected: sample distance {dist:.3f} deviates significantly from baseline dataset distribution (z-score: {z_score:.2f})",
                    evidence={
                        "embedding_distance": round(float(dist), 4),
                        "distance_cutoff": round(float(cutoff), 4),
                        "z_score": round(float(z_score), 2),
                        "contributor_id": samples[i].contributor_id,
                        "batch_id": samples[i].batch_id
                    },
                    severity=SeverityEnum.MEDIUM,
                    confidence=round(min(0.95, 0.65 + z_score * 0.1), 2),
                    disposition=DispositionEnum.REVIEW,
                    recommended_action="Validate whether this sample belongs to the target domain or was erroneously ingested.",
                    timestamp=_now_iso()
                ))

        return findings, ood_count


class TriggerPatternDetector:
    """
    Detects repeated localized trigger/patch patterns across dataset samples.
    Audits localized sub-windows (corners and bboxes) for identical or clustered patterns.
    """

    def __init__(self, patch_size: int = 16, repetition_threshold: int = 3):
        self.patch_size = patch_size
        self.repetition_threshold = repetition_threshold

    def audit(
        self,
        samples: List[DatasetSample]
    ) -> Tuple[List[Finding], int]:
        findings: List[Finding] = []
        patch_map: Dict[str, List[int]] = {}

        for idx, s in enumerate(samples):
            try:
                img = Image.open(s.image_path).convert("RGB")
                w, h = img.size
                if w < self.patch_size or h < self.patch_size:
                    continue

                # Check 4 corners for synthetic injected triggers
                corners = [
                    img.crop((w - self.patch_size, h - self.patch_size, w, h)),  # bottom-right
                    img.crop((0, 0, self.patch_size, self.patch_size)),          # top-left
                    img.crop((w - self.patch_size, 0, w, self.patch_size)),      # top-right
                    img.crop((0, h - self.patch_size, self.patch_size, h)),      # bottom-left
                ]

                for corner_idx, c_patch in enumerate(corners):
                    patch_np = np.asarray(c_patch, dtype=np.float32)
                    # Backdoor triggers have distinct texture/structure. Ignore uniform flat background!
                    if np.std(patch_np) < 8.0:
                        continue

                    # Compute perceptual hash of corner patch
                    ph = compute_phash(c_patch, hash_size=4, highfreq_factor=2)
                    key = f"c{corner_idx}_{ph}"
                    patch_map.setdefault(key, []).append(idx)
            except Exception:
                continue

        trigger_count = 0
        flagged_samples: Set[int] = set()

        for key, indices in patch_map.items():
            unique_indices = sorted(list(set(indices)))
            if len(unique_indices) >= self.repetition_threshold:
                for idx in unique_indices:
                    if idx not in flagged_samples:
                        flagged_samples.add(idx)
                        trigger_count += 1
                        findings.append(Finding(
                            finding_id=f"FIND-DS-TRIGGER-{idx:04d}",
                            module=ModuleEnum.DATA_SENTINEL,
                            asset=samples[idx].sample_id,
                            reason=f"Repeated localized trigger pattern detected across {len(unique_indices)} samples (potential backdoor patch insertion)",
                            evidence={
                                "patch_key": key,
                                "matching_sample_count": len(unique_indices),
                                "co_occurring_samples": [samples[i].sample_id for i in unique_indices[:5]],
                                "contributor_id": samples[idx].contributor_id,
                                "batch_id": samples[idx].batch_id
                            },
                            severity=SeverityEnum.HIGH,
                            confidence=0.88,
                            disposition=DispositionEnum.QUARANTINE,
                            recommended_action="Quarantine samples with repeated trigger pattern. Check for backdoor poisoning attempt.",
                            timestamp=_now_iso()
                        ))

        return findings, trigger_count
