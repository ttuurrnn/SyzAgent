#!/usr/bin/env python3
"""
SyzDirect Failure Triage Agent

Analyzes fuzzing logs to classify failure reasons:
- R1: Incomplete dependent syscall inference
- R2: Difficult parameter/object generation (filesystem images, etc.)
- R3: Insufficient deep analysis of related syscall context

Based on SyzDirect paper's Table 4 failure analysis.
"""

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional, Tuple
from enum import Enum
from pathlib import Path
import statistics


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from source.common.template_bundle import template_list


class FailureClass(Enum):
    """Failure classification from SyzDirect paper"""
    R1_MISSING_DEPS = "R1"      # Incomplete dependent syscall inference
    R2_PARAM_OBJECT = "R2"      # Difficult parameter/object generation
    R3_CONTEXT_DEPTH = "R3"     # Insufficient related syscall analysis
    SUCCESS = "SUCCESS"          # Target reached
    UNKNOWN = "UNKNOWN"          # Cannot classify
    MIXED = "MIXED"              # Multiple issues detected


@dataclass
class ExecutionLog:
    """Single execution log entry"""
    timestamp: float
    seed_id: str
    template_id: str
    syscall_distances: Dict[str, float]
    seed_distance: float
    template_distance: float
    reached_target: bool
    crash: bool
    crash_sig: Optional[str] = None
    errno_counts: Dict[str, int] = field(default_factory=dict)
    coverage_new: bool = False
    iteration: int = 0


@dataclass
class RunSummary:
    """Summary statistics for a fuzzing run"""
    target_id: str
    total_iterations: int
    total_time_seconds: float
    
    # Distance trends
    min_seed_distance: float
    avg_seed_distance: float
    distance_trend: List[float]  # Moving average over time
    plateau_detected: bool
    plateau_value: Optional[float]
    
    # Template stats
    template_match_rate: float
    template_distances: Dict[str, float]
    
    # Execution stats
    reached_target_count: int
    crash_count: int
    
    # Error analysis
    errno_distribution: Dict[str, int]
    error_rate: float
    einval_rate: float
    eperm_rate: float
    efault_rate: float
    
    # Object argument detection
    object_args_detected: bool
    fs_image_needed: bool


@dataclass
class TriageResult:
    """Result of failure triage"""
    target_id: str
    failure_class: FailureClass
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    recommended_actions: List[str]
    
    # Detailed diagnostics
    distance_analysis: Dict[str, Any]
    error_analysis: Dict[str, Any]
    template_analysis: Dict[str, Any]


class FailureTriageAgent:
    """
    Analyzes fuzzing run logs to classify failure reasons.
    Uses heuristics based on SyzDirect paper's failure analysis.
    """
    
    # Error patterns indicating specific issues
    OBJECT_ARG_PATTERNS = [
        r'mount',
        r'filesystem',
        r'image',
        r'loop',
        r'mkfs',
    ]
    
    # Common errno values
    EINVAL = -22
    EPERM = -1
    EFAULT = -14
    ENOENT = -2
    EACCES = -13
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Thresholds for classification
        self.plateau_threshold = 0.05  # Distance change threshold for plateau
        self.plateau_window = 100      # Iterations to check for plateau
        self.error_rate_threshold = 0.7  # High error rate threshold
        self.einval_threshold = 0.5    # High EINVAL rate threshold
        
    def triage(self, logs: List[ExecutionLog], 
               static_info: Dict = None) -> TriageResult:
        """
        Perform failure triage on execution logs.
        
        Args:
            logs: List of execution log entries
            static_info: Optional static analysis results
            
        Returns:
            TriageResult with classification and recommendations
        """
        if not logs:
            return self._create_unknown_result("No logs provided")
            
        # Compute summary statistics
        summary = self._compute_summary(logs)
        
        # Check for success first
        if summary.reached_target_count > 0:
            return self._create_success_result(summary)
            
        # Collect evidence for each failure class
        r1_evidence = self._check_r1(summary, logs, static_info)
        r2_evidence = self._check_r2(summary, logs)
        r3_evidence = self._check_r3(summary, logs, static_info)
        
        # Determine primary failure class
        failure_class, confidence = self._determine_class(
            r1_evidence, r2_evidence, r3_evidence
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            failure_class, r1_evidence, r2_evidence, r3_evidence
        )
        
        return TriageResult(
            target_id=summary.target_id,
            failure_class=failure_class,
            confidence=confidence,
            evidence=r1_evidence + r2_evidence + r3_evidence,
            recommended_actions=recommendations,
            distance_analysis={
                'min_distance': summary.min_seed_distance,
                'avg_distance': summary.avg_seed_distance,
                'plateau': summary.plateau_detected,
                'plateau_value': summary.plateau_value,
            },
            error_analysis={
                'error_rate': summary.error_rate,
                'einval_rate': summary.einval_rate,
                'eperm_rate': summary.eperm_rate,
                'efault_rate': summary.efault_rate,
            },
            template_analysis={
                'match_rate': summary.template_match_rate,
                'template_distances': summary.template_distances,
            },
        )
    
    def _compute_summary(self, logs: List[ExecutionLog]) -> RunSummary:
        """Compute summary statistics from logs."""
        if not logs:
            raise ValueError("No logs to summarize")
            
        distances = [log.seed_distance for log in logs 
                     if log.seed_distance < float('inf')]
        
        # Compute distance trend (moving average)
        window_size = min(50, len(distances) // 10 + 1)
        distance_trend = []
        for i in range(0, len(distances), window_size):
            window = distances[i:i+window_size]
            if window:
                distance_trend.append(statistics.mean(window))
                
        # Detect plateau
        plateau_detected = False
        plateau_value = None
        if len(distance_trend) >= 3:
            recent = distance_trend[-3:]
            if max(recent) - min(recent) < self.plateau_threshold:
                plateau_detected = True
                plateau_value = statistics.mean(recent)
                
        # Aggregate errno counts
        total_errnos: Dict[str, int] = {}
        for log in logs:
            for errno, count in log.errno_counts.items():
                total_errnos[errno] = total_errnos.get(errno, 0) + count
                
        total_errors = sum(total_errnos.values())
        total_syscalls = len(logs) * 5  # Approximate
        
        # Template statistics
        template_dists = {}
        for log in logs:
            tid = log.template_id
            if tid not in template_dists:
                template_dists[tid] = []
            template_dists[tid].append(log.template_distance)
            
        template_avg_dists = {
            tid: statistics.mean(dists) if dists else float('inf')
            for tid, dists in template_dists.items()
        }
        
        # Count template matches (where template was actually used)
        template_matches = sum(1 for log in logs if log.template_id != 'none')
        
        return RunSummary(
            target_id=logs[0].template_id.split('_')[0] if logs else 'unknown',
            total_iterations=len(logs),
            total_time_seconds=logs[-1].timestamp - logs[0].timestamp if len(logs) > 1 else 0,
            min_seed_distance=min(distances) if distances else float('inf'),
            avg_seed_distance=statistics.mean(distances) if distances else float('inf'),
            distance_trend=distance_trend,
            plateau_detected=plateau_detected,
            plateau_value=plateau_value,
            template_match_rate=template_matches / len(logs) if logs else 0,
            template_distances=template_avg_dists,
            reached_target_count=sum(1 for log in logs if log.reached_target),
            crash_count=sum(1 for log in logs if log.crash),
            errno_distribution=total_errnos,
            error_rate=total_errors / total_syscalls if total_syscalls else 0,
            einval_rate=total_errnos.get('EINVAL', 0) / total_errors if total_errors else 0,
            eperm_rate=total_errnos.get('EPERM', 0) / total_errors if total_errors else 0,
            efault_rate=total_errnos.get('EFAULT', 0) / total_errors if total_errors else 0,
            object_args_detected=False,  # Set by _check_r2
            fs_image_needed=False,  # Set by _check_r2
        )
    
    def _check_r1(self, summary: RunSummary, logs: List[ExecutionLog],
                  static_info: Dict = None) -> List[str]:
        """
        Check for R1: Incomplete dependent syscall inference.
        
        Indicators:
        - Template syscall sequence is short
        - Entry syscall executes but target never reached
        - Distance plateaus and doesn't improve across templates
        """
        evidence = []
        
        # Check for distance plateau with no improvement
        if summary.plateau_detected:
            evidence.append(
                f"R1: Distance plateau at {summary.plateau_value:.2f} detected"
            )
            
        # Check if different templates show similar results (suggesting missing deps)
        if len(summary.template_distances) > 1:
            dists = list(summary.template_distances.values())
            valid_dists = [d for d in dists if d < float('inf')]
            if valid_dists and max(valid_dists) - min(valid_dists) < 1.0:
                evidence.append(
                    "R1: Multiple templates show similar distances, suggesting common missing dependency"
                )
                
        # Check static info for short sequences
        if static_info:
            templates = template_list(static_info)
            for t in templates:
                related = t.get('related_syscalls', [])
                if len(related) < 2:
                    evidence.append(
                        f"R1: Template {t.get('template_id')} has only {len(related)} related syscalls"
                    )
                    break
                    
        return evidence
    
    def _check_r2(self, summary: RunSummary, 
                  logs: List[ExecutionLog]) -> List[str]:
        """
        Check for R2: Difficult parameter/object generation.
        
        Indicators:
        - Distance is very low (near target) but no trigger
        - High EINVAL/EFAULT rate on specific syscalls
        - Filesystem/image-related syscalls detected
        """
        evidence = []
        
        # Check for near-target but no success
        if summary.min_seed_distance < 5 and summary.reached_target_count == 0:
            evidence.append(
                f"R2: Very close to target (distance={summary.min_seed_distance:.2f}) but never reached"
            )
            
        # Check for high EINVAL rate (wrong parameters)
        if summary.einval_rate > self.einval_threshold:
            evidence.append(
                f"R2: High EINVAL rate ({summary.einval_rate:.1%}) suggests parameter issues"
            )
            
        # Check for high EFAULT rate (memory/buffer issues)
        if summary.efault_rate > 0.3:
            evidence.append(
                f"R2: High EFAULT rate ({summary.efault_rate:.1%}) suggests object/buffer issues"
            )
            
        # Check for object argument patterns in errors
        for pattern in self.OBJECT_ARG_PATTERNS:
            for errno, count in summary.errno_distribution.items():
                if pattern in errno.lower():
                    evidence.append(
                        f"R2: Object argument pattern detected: {pattern}"
                    )
                    break
                    
        return evidence
    
    def _check_r3(self, summary: RunSummary, logs: List[ExecutionLog],
                  static_info: Dict = None) -> List[str]:
        """
        Check for R3: Insufficient related syscall context analysis.
        
        Indicators:
        - Entry syscall is correct but related syscalls fail
        - High error rate on configuration syscalls (bind, setsockopt, etc.)
        - Seeds mostly fail on early-return paths
        """
        evidence = []
        
        # Check overall error rate
        if summary.error_rate > self.error_rate_threshold:
            evidence.append(
                f"R3: High overall error rate ({summary.error_rate:.1%}) suggests context setup issues"
            )
            
        # Check for EPERM (permission/capability issues)
        if summary.eperm_rate > 0.2:
            evidence.append(
                f"R3: High EPERM rate ({summary.eperm_rate:.1%}) suggests missing context setup"
            )
            
        # Check template match rate (low rate suggests template not being used effectively)
        if summary.template_match_rate < 0.5:
            evidence.append(
                f"R3: Low template match rate ({summary.template_match_rate:.1%}) suggests template not effective"
            )
            
        # Check for decreasing but still failing distance
        if len(summary.distance_trend) >= 2:
            if summary.distance_trend[-1] > 0 and summary.distance_trend[-1] < summary.distance_trend[0]:
                if summary.reached_target_count == 0:
                    evidence.append(
                        "R3: Distance decreasing but not reaching target, related syscall context may be incomplete"
                    )
                    
        return evidence
    
    def _determine_class(self, r1_evidence: List[str], 
                         r2_evidence: List[str],
                         r3_evidence: List[str]) -> Tuple[FailureClass, float]:
        """Determine primary failure class based on evidence."""
        scores = {
            FailureClass.R1_MISSING_DEPS: len(r1_evidence),
            FailureClass.R2_PARAM_OBJECT: len(r2_evidence),
            FailureClass.R3_CONTEXT_DEPTH: len(r3_evidence),
        }
        
        total = sum(scores.values())
        if total == 0:
            return FailureClass.UNKNOWN, 0.0
            
        max_class = max(scores, key=scores.get)
        max_score = scores[max_class]
        
        # Check for mixed case
        significant_classes = [c for c, s in scores.items() if s >= max_score * 0.7]
        if len(significant_classes) > 1:
            return FailureClass.MIXED, max_score / total
            
        confidence = max_score / total
        return max_class, confidence
    
    def _generate_recommendations(self, failure_class: FailureClass,
                                   r1_evidence: List[str],
                                   r2_evidence: List[str],
                                   r3_evidence: List[str]) -> List[str]:
        """Generate actionable recommendations based on failure class."""
        recommendations = []
        
        if failure_class in [FailureClass.R1_MISSING_DEPS, FailureClass.MIXED]:
            recommendations.extend([
                "Expand related syscall candidates using resource flow analysis",
                "Add more syscalls to create→configure→use sequence",
                "Check for missing initialization syscalls",
            ])
            
        if failure_class in [FailureClass.R2_PARAM_OBJECT, FailureClass.MIXED]:
            recommendations.extend([
                "Add filesystem image corpus (ext4, btrfs, f2fs variants)",
                "Constrain argument ranges based on EINVAL patterns",
                "Pre-create required objects (files, devices) before entry syscall",
            ])
            
        if failure_class in [FailureClass.R3_CONTEXT_DEPTH, FailureClass.MIXED]:
            recommendations.extend([
                "Apply argument constraint refinement to related syscalls",
                "Add context builder syscalls (socket→setsockopt→bind pattern)",
                "Analyze error-inducing syscall parameters",
            ])
            
        return recommendations
    
    def _create_success_result(self, summary: RunSummary) -> TriageResult:
        """Create result for successful runs."""
        return TriageResult(
            target_id=summary.target_id,
            failure_class=FailureClass.SUCCESS,
            confidence=1.0,
            evidence=[f"Target reached {summary.reached_target_count} times"],
            recommended_actions=["Run longer for more crashes" if summary.crash_count == 0 else "Success - crashes found"],
            distance_analysis={'min_distance': summary.min_seed_distance},
            error_analysis={'error_rate': summary.error_rate},
            template_analysis={'match_rate': summary.template_match_rate},
        )
    
    def _create_unknown_result(self, reason: str) -> TriageResult:
        """Create result for unknown/unclassifiable cases."""
        return TriageResult(
            target_id='unknown',
            failure_class=FailureClass.UNKNOWN,
            confidence=0.0,
            evidence=[reason],
            recommended_actions=["Collect more execution logs"],
            distance_analysis={},
            error_analysis={},
            template_analysis={},
        )


def load_logs(log_file: str) -> List[ExecutionLog]:
    """Load execution logs from JSON file."""
    with open(log_file, 'r') as f:
        data = json.load(f)
        
    logs = []
    for entry in data:
        log = ExecutionLog(
            timestamp=entry.get('timestamp', 0),
            seed_id=entry.get('seed_id', ''),
            template_id=entry.get('template_id', ''),
            syscall_distances=entry.get('syscall_distances', {}),
            seed_distance=entry.get('seed_distance', float('inf')),
            template_distance=entry.get('template_distance', float('inf')),
            reached_target=entry.get('reached_target', False),
            crash=entry.get('crash', False),
            crash_sig=entry.get('crash_sig'),
            errno_counts=entry.get('errno_counts', {}),
            coverage_new=entry.get('coverage_new', False),
            iteration=entry.get('iteration', 0),
        )
        logs.append(log)
        
    return logs


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SyzDirect Failure Triage Agent')
    parser.add_argument('--logs', required=True, help='Execution logs JSON')
    parser.add_argument('--static-info', help='Static analysis results JSON')
    parser.add_argument('--output', default='triage_result.json', help='Output file')
    
    args = parser.parse_args()
    
    # Load inputs
    logs = load_logs(args.logs)
    
    static_info = None
    if args.static_info:
        with open(args.static_info, 'r') as f:
            static_info = json.load(f)
            
    # Perform triage
    agent = FailureTriageAgent()
    result = agent.triage(logs, static_info)
    
    # Output result
    result_dict = {
        'target_id': result.target_id,
        'failure_class': result.failure_class.value,
        'confidence': result.confidence,
        'evidence': result.evidence,
        'recommended_actions': result.recommended_actions,
        'distance_analysis': result.distance_analysis,
        'error_analysis': result.error_analysis,
        'template_analysis': result.template_analysis,
    }
    
    with open(args.output, 'w') as f:
        json.dump(result_dict, f, indent=2)
        
    print(f"\n[+] Triage complete")
    print(f"    Failure class: {result.failure_class.value}")
    print(f"    Confidence: {result.confidence:.1%}")
    print(f"    Evidence count: {len(result.evidence)}")
    print(f"    Recommendations: {len(result.recommended_actions)}")
