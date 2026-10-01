"""
Unit Tests for Blast Radius Traceability (Gate G)
"""

import unittest
from visionguard.core.schemas import SeverityEnum
from visionguard.modules.blast_radius.tracer import BlastRadiusGraph


class TestBlastRadius(unittest.TestCase):
    def setUp(self):
        self.graph = BlastRadiusGraph()
        # Register branch 1
        self.graph.register_lineage(
            contributor_id="Contributor_B",
            batch_id="Batch_17",
            dataset_id="Dataset_X",
            model_id="Model_Y",
            inference_record_ids=["REC-001", "REC-002", "REC-003"]
        )
        # Register branch 2 (unrelated clean contributor)
        self.graph.register_lineage(
            contributor_id="Contributor_Clean",
            batch_id="Batch_99",
            dataset_id="Dataset_Safe",
            model_id="Model_Safe",
            inference_record_ids=["REC-888"]
        )

    def test_blast_radius_tracing(self):
        trace = self.graph.trace_impact("Contributor_B")

        self.assertEqual(trace.root_contributor, "Contributor_B")
        self.assertIn("Dataset_X", trace.affected_datasets)
        self.assertIn("Model_Y", trace.affected_models)
        self.assertEqual(len(trace.affected_inference_records), 3)
        self.assertEqual(trace.severity, SeverityEnum.CRITICAL)

        # Ensure clean branch is not contaminated
        self.assertNotIn("Model_Safe", trace.affected_models)
        self.assertNotIn("REC-888", trace.affected_inference_records)

    def test_mermaid_export(self):
        mermaid_code = self.graph.to_mermaid()
        self.assertTrue(mermaid_code.startswith("graph TD"))
        self.assertIn("Contributor_B", mermaid_code)
        self.assertIn("Model_Y", mermaid_code)

    def test_dict_export(self):
        d = self.graph.to_dict()
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertGreaterEqual(len(d["edges"]), 5)


if __name__ == "__main__":
    unittest.main()
