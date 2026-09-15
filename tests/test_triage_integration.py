import unittest
from unittest import mock

from source.agent.distance_enhancement_agent import DistanceEnhancementAgent
from source.agent.failure_triage import FailureClass, TriageResult, serialize_triage_result
from syzagent.pipeline import SyzAgentPipeline


class FailureTriageSerializationTest(unittest.TestCase):
    def test_serialize_triage_result_includes_target_metadata(self):
        result = TriageResult(
            target_id="teql_case",
            failure_class=FailureClass.R4_DISTANCE_STALL,
            confidence=0.9,
            evidence=["distance stalled"],
            recommended_actions=["query roadmap"],
            distance_analysis={"min_distance": 7},
            error_analysis={},
            template_analysis={},
        )
        static_info = {
            "target_id": "teql_case",
            "function": "teql_master_xmit",
            "file_path": "net/sched/sch_teql.c",
        }

        payload = serialize_triage_result(result, static_info)

        self.assertEqual(payload["target_info"]["function"], "teql_master_xmit")
        self.assertEqual(payload["target_info"]["func_path"], "net/sched/sch_teql.c")
        self.assertEqual(payload["static_info"]["target_id"], "teql_case")


class DistanceEnhancementAgentTest(unittest.TestCase):
    def test_distance_agent_builds_minimal_roadmap_from_triage_summary(self):
        template_bundle = {
            "target_id": "teql_case",
            "templates": [
                {
                    "template_id": "tmpl0",
                    "target_id": "teql_case",
                    "entry_syscall": {
                        "name": "sendmsg",
                        "syzlang_name": "sendmsg$nl_route_sched",
                    },
                    "related_syscalls": [
                        {
                            "name": "socket",
                            "syzlang_name": "socket$nl_route",
                        }
                    ],
                }
            ],
        }
        triage_result = {
            "failure_class": "R4",
            "distance_analysis": {"min_distance": 12},
            "static_info": {
                "function": "teql_master_xmit",
                "file_path": "net/sched/sch_teql.c",
            },
        }

        observed = {}

        def fake_llm(current_callfile, roadmap, target_function, target_file, source_snippets=""):
            observed["current_callfile"] = current_callfile
            observed["roadmap"] = roadmap
            observed["target_function"] = target_function
            observed["target_file"] = target_file
            return [{"Target": "sendmsg$nl_route_sched", "Relate": ["socket$nl_route"]}]

        with mock.patch(
            "source.agent.distance_enhancement_agent.llm_enhance_callfile_for_distance",
            side_effect=fake_llm,
        ):
            enhanced = DistanceEnhancementAgent(template_bundle, triage_result).analyze_and_enhance()

        self.assertEqual(observed["roadmap"]["current_dist_min"], 12)
        self.assertEqual(observed["target_function"], "teql_master_xmit")
        self.assertEqual(observed["target_file"], "net/sched/sch_teql.c")
        self.assertEqual(enhanced[0]["entry_syscall"]["syzlang_name"], "sendmsg$nl_route_sched")


class SyzAgentPipelineTest(unittest.TestCase):
    def test_resolve_triage_static_info_prefers_target_argument(self):
        args = type(
            "Args",
            (),
            {
                "output": "syzagent_output",
                "target": "targets/example_target.json",
                "case": None,
                "mode": "agent-loop",
                "budget_hours": 1.0,
            },
        )()
        pipeline = SyzAgentPipeline(args)
        self.assertTrue(pipeline._resolve_triage_static_info().endswith("targets/example_target.json"))


if __name__ == "__main__":
    unittest.main()
