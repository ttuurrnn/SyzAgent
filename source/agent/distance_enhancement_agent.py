#!/usr/bin/env python3
"""
SyzDirect Distance Stagnation Agent (R4 Response)

Addresses R4 failures: "Coverage grows but distance to target stagnant"

Uses LLM-driven analysis of the distance roadmap and kernel source to
suggest better syscall sequences.
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_DIR = REPO_ROOT / "source" / "syzdirect" / "Runner"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

# SyzDirect Runner imports
from llm_enhance import llm_enhance_callfile_for_distance
from agent_triage import templates_to_callfile, callfile_to_templates
from source.common.template_bundle import normalize_template_bundle, template_list


class DistanceEnhancementAgent:
    """
    Agent for overcoming distance stagnation.
    Addresses R4 failures from SyzDirect.
    """

    def __init__(self, template_bundle: Dict, triage_result: Dict):
        self.template_bundle = template_bundle
        self.triage_result = triage_result
        self.target_info = self._resolve_target_info()
        self.roadmap = self._resolve_roadmap()

    def _resolve_target_info(self) -> Dict:
        merged: Dict = {}
        candidates = [
            self.triage_result.get("target_info"),
            self.triage_result.get("static_info"),
            self.template_bundle.get("target_info"),
            self.template_bundle.get("target_spec"),
            self.template_bundle,
        ]
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            for src, dst in (
                ("target_id", "target_id"),
                ("function", "function"),
                ("file_path", "file_path"),
                ("func_path", "func_path"),
                ("kernel_commit", "kernel_commit"),
            ):
                value = candidate.get(src)
                if value not in (None, "") and dst not in merged:
                    merged[dst] = value
        if "func_path" not in merged and merged.get("file_path"):
            merged["func_path"] = merged["file_path"]
        return merged

    def _resolve_roadmap(self) -> Dict:
        distance_analysis = self.triage_result.get("distance_analysis", {})
        roadmap = distance_analysis.get("roadmap")
        if isinstance(roadmap, dict) and roadmap.get("current_dist_min") not in (None, ""):
            return roadmap

        min_distance = distance_analysis.get("min_distance")
        if not isinstance(min_distance, (int, float)) or min_distance <= 0:
            return {}

        target_func = self.target_info.get("function", "")
        target_file = self.target_info.get("func_path") or self.target_info.get("file_path", "")
        return {
            "target_function": target_func,
            "current_dist_min": min_distance,
            "stepping_stones": [],
            "total_functions_in_range": 0,
            "target_file": target_file,
        }

    def analyze_and_enhance(self) -> List[Dict]:
        """
        Use SyzDirect's LLM enhancement to suggest new templates.
        """
        if not self.roadmap:
            print("[DistanceEnhancementAgent] Warning: No roadmap in triage result")
            return []

        # 1. Convert current templates to callfile format
        templates = template_list(self.template_bundle)
        if not templates:
            print("[DistanceEnhancementAgent] Warning: No templates found")
            return []
        current_callfile = templates_to_callfile(templates)

        # 2. Call LLM-driven enhancement
        # We need target function and file from triage or static info
        target_func = self.target_info.get("function")
        target_file = self.target_info.get("func_path") or self.target_info.get("file_path")

        if not target_func:
            print("[DistanceEnhancementAgent] Error: target_function missing")
            return []

        print(f"[DistanceEnhancementAgent] Calling LLM to enhance for {target_func}...")

        enhanced_callfile = llm_enhance_callfile_for_distance(
            current_callfile=current_callfile,
            roadmap=self.roadmap,
            target_function=target_func,
            target_file=target_file,
            source_snippets=self.triage_result.get("source_snippets", ""),
        )

        if not enhanced_callfile:
            print("[DistanceEnhancementAgent] LLM returned no enhancements")
            return []

        # 3. Convert back to template bundle format
        new_templates = callfile_to_templates(enhanced_callfile)

        return new_templates


def enhance_templates(template_file: str, triage_file: str, output_file: str):
    """Main entry point for template enhancement."""
    with open(template_file, 'r') as f:
        template_data = json.load(f)

    with open(triage_file, 'r') as f:
        triage_result = json.load(f)

    agent = DistanceEnhancementAgent(template_data, triage_result)
    enhanced = agent.analyze_and_enhance()

    if not enhanced:
        print("[DistanceEnhancementAgent] No changes made.")
        return []

    output = {
        'original_template_count': len(template_list(template_data)),
        'enhanced_template_count': len(enhanced),
        'reasoning': triage_result.get('reasoning', 'LLM-driven distance enhancement'),
    }
    output.update(
        normalize_template_bundle(
            enhanced,
            default_target_id=template_data.get("target_id", "unknown"),
        )
    )

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"[+] Generated {len(enhanced)} enhanced templates via LLM")
    return enhanced


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Distance Stagnation Agent')
    parser.add_argument('--templates', required=True, help='Template JSON file')
    parser.add_argument('--triage', required=True, help='Triage result JSON')
    parser.add_argument('--output', default='enhanced_templates.json', help='Output file')

    args = parser.parse_args()
    enhance_templates(args.templates, args.triage, args.output)
