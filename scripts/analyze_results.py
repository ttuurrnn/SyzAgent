#!/usr/bin/env python3
"""
SyzDirect Results Analyzer and Report Generator

Analyzes experiment results and generates comparative reports.
Computes key metrics: hitting-round, TTE, failure class distribution.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path
import statistics
from datetime import datetime


@dataclass
class ExperimentResult:
    """Single experiment run result"""
    run_id: str
    experiment_type: str  # baseline, syzdirect, agent-loop
    target_id: str
    
    # Time metrics
    start_time: datetime
    end_time: datetime
    total_duration_seconds: float
    
    # Success metrics
    target_reached: bool
    time_to_exposure_seconds: Optional[float]  # TTE
    hitting_round: Optional[int]  # For agent-loop
    
    # Coverage metrics
    corpus_size: int
    crash_count: int
    unique_crashes: int
    
    # Distance metrics (for directed approaches)
    min_distance: Optional[float]
    final_distance: Optional[float]
    distance_improvement: Optional[float]
    
    # Failure analysis (for agent-loop)
    failure_class: Optional[str]
    rounds_completed: int = 0
    improvement_rounds: int = 0


@dataclass
class ComparativeReport:
    """Comparative analysis across experiment types"""
    target_id: str
    
    # Per-approach summaries
    baseline_results: List[ExperimentResult]
    syzdirect_results: List[ExperimentResult]
    agent_loop_results: List[ExperimentResult]
    
    # Comparative metrics
    baseline_tte_avg: Optional[float]
    syzdirect_tte_avg: Optional[float]
    agent_loop_tte_avg: Optional[float]
    
    syzdirect_speedup: Optional[float]  # vs baseline
    agent_loop_speedup: Optional[float]  # vs syzdirect
    
    # Success rates
    baseline_success_rate: float
    syzdirect_success_rate: float
    agent_loop_success_rate: float
    
    # Failure class breakdown (for agent-loop)
    failure_class_distribution: Dict[str, int]
    failure_class_improvements: Dict[str, float]


class ResultsAnalyzer:
    """Analyzes experiment results and generates reports."""
    
    def __init__(self, runs_dir: str):
        self.runs_dir = Path(runs_dir)
        self.results: Dict[str, List[ExperimentResult]] = {
            'baseline': [],
            'syzdirect': [],
            'agent-loop': [],
        }
        
    def load_results(self):
        """Load all experiment results from runs directory."""
        
        # Load baseline results
        baseline_dir = self.runs_dir / 'baseline-syzkaller'
        if baseline_dir.exists():
            for run_dir in baseline_dir.iterdir():
                if run_dir.is_dir():
                    result = self._load_run_result(run_dir, 'baseline')
                    if result:
                        self.results['baseline'].append(result)
                        
        # Load syzdirect results
        syzdirect_dir = self.runs_dir / 'baseline-syzdirect'
        if syzdirect_dir.exists():
            for run_dir in syzdirect_dir.iterdir():
                if run_dir.is_dir():
                    result = self._load_run_result(run_dir, 'syzdirect')
                    if result:
                        self.results['syzdirect'].append(result)
                        
        # Load agent-loop results
        agent_dir = self.runs_dir / 'agent-loop'
        if agent_dir.exists():
            for run_dir in agent_dir.iterdir():
                if run_dir.is_dir():
                    result = self._load_run_result(run_dir, 'agent-loop')
                    if result:
                        self.results['agent-loop'].append(result)
                        
        print(f"Loaded results: baseline={len(self.results['baseline'])}, "
              f"syzdirect={len(self.results['syzdirect'])}, "
              f"agent-loop={len(self.results['agent-loop'])}")
              
    def _load_run_result(self, run_dir: Path, 
                         exp_type: str) -> Optional[ExperimentResult]:
        """Load result from a single run directory."""
        try:
            results_file = run_dir / 'results.json'
            if not results_file.exists():
                return None
                
            with open(results_file) as f:
                data = json.load(f)
                
            # Parse timestamps
            timestamp_str = data.get('timestamp', datetime.now().isoformat())
            try:
                end_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                end_time = datetime.now()
                
            # Get start time from directory name or log
            start_time = end_time  # Default to end time
            
            # Load additional metrics for agent-loop
            failure_class = None
            rounds_completed = 0
            hitting_round = None
            
            if exp_type == 'agent-loop':
                report_file = run_dir / 'final_report.json'
                if report_file.exists():
                    with open(report_file) as f:
                        report = json.load(f)
                    rounds_completed = report.get('total_rounds', 0)
                    
                    # Check rounds for success
                    for i, round_data in enumerate(report.get('rounds', [])):
                        if round_data.get('failure_class') == 'SUCCESS':
                            hitting_round = i + 1
                            break
                        failure_class = round_data.get('failure_class')
                        
            # Load distance metrics
            min_distance = None
            if exp_type in ['syzdirect', 'agent-loop']:
                distances_file = run_dir / 'distances' / 'distances.json'
                if distances_file.exists():
                    with open(distances_file) as f:
                        dist_data = json.load(f)
                    # Get minimum from syscall distances
                    syscall_dists = dist_data.get('syscall_entry_distances', {})
                    if syscall_dists:
                        min_distance = min(syscall_dists.values())
                        
            return ExperimentResult(
                run_id=run_dir.name,
                experiment_type=exp_type,
                target_id=data.get('target_id', run_dir.name.split('_')[0]),
                start_time=start_time,
                end_time=end_time,
                total_duration_seconds=(end_time - start_time).total_seconds(),
                target_reached=hitting_round is not None or data.get('crashes', 0) > 0,
                time_to_exposure_seconds=None,  # Would need crash timing
                hitting_round=hitting_round,
                corpus_size=data.get('corpus_size', 0),
                crash_count=data.get('crashes', 0),
                unique_crashes=data.get('crashes', 0),  # Simplified
                min_distance=min_distance,
                final_distance=min_distance,
                distance_improvement=None,
                failure_class=failure_class,
                rounds_completed=rounds_completed,
            )
            
        except Exception as e:
            print(f"Error loading {run_dir}: {e}")
            return None
            
    def generate_comparative_report(self, target_id: str = None) -> ComparativeReport:
        """Generate comparative report for a target or all targets."""
        
        # Filter results by target if specified
        baseline = self.results['baseline']
        syzdirect = self.results['syzdirect']
        agent_loop = self.results['agent-loop']
        
        if target_id:
            baseline = [r for r in baseline if r.target_id == target_id]
            syzdirect = [r for r in syzdirect if r.target_id == target_id]
            agent_loop = [r for r in agent_loop if r.target_id == target_id]
            
        # Compute TTE averages
        def avg_tte(results):
            ttes = [r.time_to_exposure_seconds for r in results 
                    if r.time_to_exposure_seconds is not None]
            return statistics.mean(ttes) if ttes else None
            
        baseline_tte = avg_tte(baseline)
        syzdirect_tte = avg_tte(syzdirect)
        agent_tte = avg_tte(agent_loop)
        
        # Compute speedups
        def compute_speedup(faster, slower):
            if faster and slower and faster > 0:
                return slower / faster
            return None
            
        syzdirect_speedup = compute_speedup(syzdirect_tte, baseline_tte)
        agent_speedup = compute_speedup(agent_tte, syzdirect_tte)
        
        # Compute success rates
        def success_rate(results):
            if not results:
                return 0.0
            return sum(1 for r in results if r.target_reached) / len(results)
            
        # Failure class distribution (for agent-loop)
        failure_dist = {}
        for r in agent_loop:
            if r.failure_class:
                failure_dist[r.failure_class] = failure_dist.get(r.failure_class, 0) + 1
                
        # Improvement rates per failure class
        improvements = {}
        for fc in failure_dist:
            fc_results = [r for r in agent_loop if r.failure_class == fc]
            if fc_results:
                improved = sum(1 for r in fc_results if r.target_reached)
                improvements[fc] = improved / len(fc_results)
                
        return ComparativeReport(
            target_id=target_id or 'all',
            baseline_results=baseline,
            syzdirect_results=syzdirect,
            agent_loop_results=agent_loop,
            baseline_tte_avg=baseline_tte,
            syzdirect_tte_avg=syzdirect_tte,
            agent_loop_tte_avg=agent_tte,
            syzdirect_speedup=syzdirect_speedup,
            agent_loop_speedup=agent_speedup,
            baseline_success_rate=success_rate(baseline),
            syzdirect_success_rate=success_rate(syzdirect),
            agent_loop_success_rate=success_rate(agent_loop),
            failure_class_distribution=failure_dist,
            failure_class_improvements=improvements,
        )
        
    def print_report(self, report: ComparativeReport):
        """Print formatted report."""
        print("\n" + "="*60)
        print(f"COMPARATIVE REPORT: {report.target_id}")
        print("="*60)
        
        print("\n## Run Counts")
        print(f"  Baseline:    {len(report.baseline_results)} runs")
        print(f"  SyzDirect:   {len(report.syzdirect_results)} runs")
        print(f"  Agent-Loop:  {len(report.agent_loop_results)} runs")
        
        print("\n## Success Rates")
        print(f"  Baseline:    {report.baseline_success_rate:.1%}")
        print(f"  SyzDirect:   {report.syzdirect_success_rate:.1%}")
        print(f"  Agent-Loop:  {report.agent_loop_success_rate:.1%}")
        
        if report.baseline_tte_avg or report.syzdirect_tte_avg or report.agent_loop_tte_avg:
            print("\n## Time-to-Exposure (TTE)")
            if report.baseline_tte_avg:
                print(f"  Baseline:    {report.baseline_tte_avg:.1f}s")
            if report.syzdirect_tte_avg:
                print(f"  SyzDirect:   {report.syzdirect_tte_avg:.1f}s")
            if report.agent_loop_tte_avg:
                print(f"  Agent-Loop:  {report.agent_loop_tte_avg:.1f}s")
                
        if report.syzdirect_speedup or report.agent_loop_speedup:
            print("\n## Speedups")
            if report.syzdirect_speedup:
                print(f"  SyzDirect vs Baseline: {report.syzdirect_speedup:.2f}x")
            if report.agent_loop_speedup:
                print(f"  Agent-Loop vs SyzDirect: {report.agent_loop_speedup:.2f}x")
                
        if report.failure_class_distribution:
            print("\n## Failure Class Distribution (Agent-Loop)")
            for fc, count in sorted(report.failure_class_distribution.items()):
                improvement = report.failure_class_improvements.get(fc, 0)
                print(f"  {fc}: {count} cases ({improvement:.1%} improved)")
                
        print("\n" + "="*60)
        
    def export_report(self, report: ComparativeReport, output_file: str):
        """Export report to JSON file."""
        data = {
            'target_id': report.target_id,
            'generated_at': datetime.now().isoformat(),
            'run_counts': {
                'baseline': len(report.baseline_results),
                'syzdirect': len(report.syzdirect_results),
                'agent_loop': len(report.agent_loop_results),
            },
            'success_rates': {
                'baseline': report.baseline_success_rate,
                'syzdirect': report.syzdirect_success_rate,
                'agent_loop': report.agent_loop_success_rate,
            },
            'tte_averages': {
                'baseline': report.baseline_tte_avg,
                'syzdirect': report.syzdirect_tte_avg,
                'agent_loop': report.agent_loop_tte_avg,
            },
            'speedups': {
                'syzdirect_vs_baseline': report.syzdirect_speedup,
                'agent_loop_vs_syzdirect': report.agent_loop_speedup,
            },
            'failure_analysis': {
                'distribution': report.failure_class_distribution,
                'improvement_rates': report.failure_class_improvements,
            },
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"Report exported to {output_file}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SyzDirect Results Analyzer')
    parser.add_argument('--runs-dir', default='/work/runs', help='Runs directory')
    parser.add_argument('--target', help='Specific target ID to analyze')
    parser.add_argument('--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    analyzer = ResultsAnalyzer(args.runs_dir)
    analyzer.load_results()
    
    report = analyzer.generate_comparative_report(args.target)
    analyzer.print_report(report)
    
    if args.output:
        analyzer.export_report(report, args.output)
