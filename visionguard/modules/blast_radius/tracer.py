"""
Blast Radius Traceability Engine for VisionGuard

Maintains the forensic lifecycle dependency graph:
Contributor -> Batch -> Dataset -> Model -> Inference -> Output

Traces downstream recorded impact when upstream assets or contributors are quarantined.

IMPORTANT CLAIM:
This performs source and attack-path attribution within the recorded asset lineage.
It does NOT claim automatic identification of real-world physical identity, IP addresses, or geolocations.
"""

from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple
from visionguard.core.schemas import BlastRadiusTrace, SeverityEnum


class BlastRadiusGraph:
    """Directed dependency graph connecting CV lifecycle entities."""

    def __init__(self):
        # Forward edges: parent -> set of children
        self._forward: Dict[str, Set[str]] = defaultdict(set)
        # Reverse edges: child -> set of parents
        self._reverse: Dict[str, Set[str]] = defaultdict(set)
        # Node metadata: node_id -> {type, metadata}
        self._nodes: Dict[str, Dict[str, Any]] = {}

    def add_node(self, node_id: str, node_type: str, metadata: Optional[Dict[str, Any]] = None):
        """Register a node: type in ('contributor', 'batch', 'dataset', 'model', 'inference', 'output')."""
        self._nodes[node_id] = {
            "type": node_type.lower(),
            "metadata": metadata or {}
        }

    def add_edge(self, source_id: str, target_id: str):
        """Add directed dependency link (source -> target)."""
        self._forward[source_id].add(target_id)
        self._reverse[target_id].add(source_id)

    def register_lineage(
        self,
        contributor_id: str,
        batch_id: str,
        dataset_id: str,
        model_id: Optional[str] = None,
        inference_record_ids: Optional[List[str]] = None
    ):
        """Convenience method to link an end-to-end lifecycle branch."""
        self.add_node(contributor_id, "contributor")
        self.add_node(batch_id, "batch")
        self.add_node(dataset_id, "dataset")

        self.add_edge(contributor_id, batch_id)
        self.add_edge(batch_id, dataset_id)

        if model_id:
            self.add_node(model_id, "model")
            self.add_edge(dataset_id, model_id)

            if inference_record_ids:
                for rec_id in inference_record_ids:
                    self.add_node(rec_id, "inference")
                    self.add_edge(model_id, rec_id)

    def trace_impact(self, root_id: str) -> BlastRadiusTrace:
        """
        Traverse downstream descendants starting from root_id using BFS.
        Returns all impacted datasets, models, and inference records.
        """
        if root_id not in self._nodes:
            return BlastRadiusTrace(
                description=f"Node '{root_id}' not found in provenance graph."
            )

        root_type = self._nodes[root_id]["type"]
        visited: Set[str] = set()
        queue = deque([root_id])

        affected_datasets: List[str] = []
        affected_models: List[str] = []
        affected_inferences: List[str] = []

        while queue:
            curr = queue.popleft()
            for child in self._forward.get(curr, set()):
                if child not in visited:
                    visited.add(child)
                    queue.append(child)
                    ctype = self._nodes.get(child, {}).get("type", "")
                    if ctype == "dataset":
                        affected_datasets.append(child)
                    elif ctype == "model":
                        affected_models.append(child)
                    elif ctype == "inference":
                        affected_inferences.append(child)

        total_impact = len(affected_datasets) + len(affected_models) + len(affected_inferences)
        
        # Determine severity based on depth of downstream infection
        if len(affected_inferences) > 0:
            severity = SeverityEnum.CRITICAL
        elif len(affected_models) > 0:
            severity = SeverityEnum.HIGH
        elif len(affected_datasets) > 0:
            severity = SeverityEnum.MEDIUM
        else:
            severity = SeverityEnum.LOW

        desc = (
            f"Downstream blast radius for {root_type} '{root_id}': "
            f"Impacts {len(affected_datasets)} dataset(s), "
            f"{len(affected_models)} trained model(s), and "
            f"{len(affected_inferences)} operational inference record(s)."
        )

        return BlastRadiusTrace(
            root_contributor=root_id if root_type == "contributor" else None,
            root_batch=root_id if root_type == "batch" else None,
            affected_datasets=sorted(list(set(affected_datasets))),
            affected_models=sorted(list(set(affected_models))),
            affected_inference_records=sorted(list(set(affected_inferences))),
            total_downstream_impact_count=total_impact,
            severity=severity,
            description=desc
        )

    def to_mermaid(self, root_id: Optional[str] = None) -> str:
        """Export subgraph or entire graph to Mermaid diagram syntax."""
        lines = ["graph TD"]
        # Render edges
        for src, targets in sorted(self._forward.items()):
            src_type = self._nodes.get(src, {}).get("type", "node")
            for tgt in sorted(targets):
                tgt_type = self._nodes.get(tgt, {}).get("type", "node")
                lines.append(f'    {src}["{src} ({src_type})"] --> {tgt}["{tgt} ({tgt_type})"]')
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export serialized representation of graph."""
        return {
            "nodes": self._nodes,
            "edges": [{"from": s, "to": t} for s, targets in self._forward.items() for t in targets]
        }
