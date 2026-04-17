#!/usr/bin/env python3
"""
SyzDirect Distance Calculator

Computes basic-block level distances from syscall entries to target locations.
Based on AFLGo distance calculation adapted for kernel fuzzing.

Distance hierarchy:
- syscall_distance: min BB distance during syscall execution
- seed_distance: min syscall distance across seed's syscalls
- template_distance: avg of top-5 shortest seed distances for template
"""

import os
import re
import json
import subprocess
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
import math


@dataclass
class BasicBlock:
    """Represents a basic block in CFG"""
    id: str
    function: str
    file: str
    line_start: int
    line_end: int
    successors: List[str] = field(default_factory=list)
    distance_to_target: float = float('inf')


@dataclass
class CallGraphNode:
    """Represents a function in call graph"""
    name: str
    file: str
    callees: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)
    basic_blocks: List[str] = field(default_factory=list)
    min_distance: float = float('inf')


@dataclass
class DistanceInfo:
    """Distance computation results"""
    target_id: str
    bb_distances: Dict[str, float] = field(default_factory=dict)
    func_distances: Dict[str, float] = field(default_factory=dict)
    syscall_entry_distances: Dict[str, float] = field(default_factory=dict)
    

class DistanceCalculator:
    """
    Calculates distances from code locations to target.
    Uses MLTA-based call graph and CFG analysis.
    """
    
    def __init__(self, kernel_src: str, kernel_build: str = None):
        self.kernel_src = Path(kernel_src)
        self.kernel_build = Path(kernel_build) if kernel_build else None
        self.call_graph: Dict[str, CallGraphNode] = {}
        self.basic_blocks: Dict[str, BasicBlock] = {}
        self.target_bbs: Set[str] = set()
        
    def compute_distances(self, target_file: str, target_line: int,
                          target_func: str = None) -> DistanceInfo:
        """
        Main entry point for distance computation.
        
        Args:
            target_file: Path to target source file
            target_line: Target line number
            target_func: Optional target function name
            
        Returns:
            DistanceInfo with computed distances
        """
        print(f"[*] Computing distances to {target_file}:{target_line}")
        
        # Step 1: Build call graph (simplified - would use LLVM in production)
        self._build_call_graph(target_file)
        
        # Step 2: Build CFG for relevant functions
        self._build_cfg(target_file, target_func)
        
        # Step 3: Mark target basic blocks
        self._mark_target_bbs(target_file, target_line)
        
        # Step 4: Compute BB distances using BFS from target
        self._compute_bb_distances()
        
        # Step 5: Compute function distances
        self._compute_func_distances()
        
        # Step 6: Compute syscall entry distances
        syscall_distances = self._compute_syscall_distances()
        
        target_id = f"{Path(target_file).name}:{target_line}"
        
        return DistanceInfo(
            target_id=target_id,
            bb_distances=dict(self.basic_blocks.items()),
            func_distances={n: g.min_distance for n, g in self.call_graph.items()},
            syscall_entry_distances=syscall_distances,
        )
    
    def _build_call_graph(self, target_file: str):
        """
        Build call graph for kernel.
        Simplified implementation - production would use LLVM/SVF.
        """
        print("[*] Building call graph...")
        
        # Extract function calls from source (simplified)
        target_path = self.kernel_src / target_file
        if not target_path.exists():
            return
            
        try:
            # Use ctags or simple parsing to find function definitions
            result = subprocess.run(
                ['grep', '-rn', r'^\w.*\s\+\w\+\s*(', str(target_path.parent)],
                capture_output=True, text=True, timeout=60
            )
            
            func_pattern = re.compile(
                r'^([^:]+):(\d+):\s*(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)'
            )
            
            for line in result.stdout.split('\n'):
                match = func_pattern.match(line)
                if match:
                    file_path, line_no, func_name = match.groups()
                    if func_name not in self.call_graph:
                        self.call_graph[func_name] = CallGraphNode(
                            name=func_name,
                            file=file_path,
                        )
                        
        except Exception as e:
            print(f"[!] Error building call graph: {e}")
            
        print(f"[+] Found {len(self.call_graph)} functions")
    
    def _build_cfg(self, target_file: str, target_func: str = None):
        """
        Build control flow graph for functions.
        Simplified implementation using source analysis.
        """
        print("[*] Building CFG...")
        
        target_path = self.kernel_src / target_file
        if not target_path.exists():
            return
            
        try:
            with open(target_path, 'r') as f:
                lines = f.readlines()
                
            current_func = None
            current_bb_id = None
            bb_counter = 0
            
            for i, line in enumerate(lines, 1):
                # Detect function start
                func_match = re.match(
                    r'^(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*{?\s*$',
                    line.strip()
                )
                if func_match:
                    current_func = func_match.group(1)
                    bb_counter = 0
                    
                # Detect basic block boundaries (simplified)
                if current_func and (
                    '{' in line or
                    re.search(r'\b(if|else|for|while|switch|case|goto)\b', line) or
                    ':' in line  # label
                ):
                    bb_counter += 1
                    bb_id = f"{current_func}_bb{bb_counter}"
                    
                    self.basic_blocks[bb_id] = BasicBlock(
                        id=bb_id,
                        function=current_func,
                        file=target_file,
                        line_start=i,
                        line_end=i,
                    )
                    
                    if current_bb_id:
                        self.basic_blocks[current_bb_id].successors.append(bb_id)
                    current_bb_id = bb_id
                    
        except Exception as e:
            print(f"[!] Error building CFG: {e}")
            
        print(f"[+] Created {len(self.basic_blocks)} basic blocks")
    
    def _mark_target_bbs(self, target_file: str, target_line: int):
        """Mark basic blocks containing or near target line."""
        for bb_id, bb in self.basic_blocks.items():
            if bb.file == target_file:
                if bb.line_start <= target_line <= bb.line_end:
                    self.target_bbs.add(bb_id)
                    bb.distance_to_target = 0
                    
        # If no exact match, find closest BB
        if not self.target_bbs:
            closest_bb = None
            min_dist = float('inf')
            
            for bb_id, bb in self.basic_blocks.items():
                if bb.file == target_file:
                    dist = abs(bb.line_start - target_line)
                    if dist < min_dist:
                        min_dist = dist
                        closest_bb = bb_id
                        
            if closest_bb:
                self.target_bbs.add(closest_bb)
                self.basic_blocks[closest_bb].distance_to_target = 0
                
        print(f"[+] Marked {len(self.target_bbs)} target basic blocks")
    
    def _compute_bb_distances(self):
        """
        Compute distances from all BBs to target BBs using reverse BFS.
        Distance = number of edges to reach target.
        """
        print("[*] Computing BB distances...")
        
        # Build reverse graph
        reverse_edges: Dict[str, List[str]] = {bb_id: [] for bb_id in self.basic_blocks}
        for bb_id, bb in self.basic_blocks.items():
            for succ in bb.successors:
                if succ in reverse_edges:
                    reverse_edges[succ].append(bb_id)
                    
        # BFS from target BBs
        from collections import deque
        
        queue = deque()
        for target_bb in self.target_bbs:
            queue.append((target_bb, 0))
            
        visited = set(self.target_bbs)
        
        while queue:
            bb_id, dist = queue.popleft()
            self.basic_blocks[bb_id].distance_to_target = dist
            
            for pred in reverse_edges.get(bb_id, []):
                if pred not in visited:
                    visited.add(pred)
                    queue.append((pred, dist + 1))
                    
        # Count reachable BBs
        reachable = sum(1 for bb in self.basic_blocks.values() 
                        if bb.distance_to_target < float('inf'))
        print(f"[+] {reachable}/{len(self.basic_blocks)} BBs can reach target")
    
    def _compute_func_distances(self):
        """
        Compute function-level distances.
        Function distance = min BB distance within function.
        """
        for func_name, node in self.call_graph.items():
            min_dist = float('inf')
            
            for bb_id, bb in self.basic_blocks.items():
                if bb.function == func_name:
                    if bb.distance_to_target < min_dist:
                        min_dist = bb.distance_to_target
                        
            node.min_distance = min_dist
            
    def _compute_syscall_distances(self) -> Dict[str, float]:
        """
        Compute distances from syscall entry points.
        Maps syscall names to their minimum distance to target.
        """
        syscall_distances = {}
        
        # Common syscall entry patterns
        syscall_pattern = re.compile(r'(sys_\w+|__x64_sys_\w+|SYSCALL_DEFINE)')
        
        for func_name, node in self.call_graph.items():
            if syscall_pattern.search(func_name):
                # Clean up syscall name
                clean_name = func_name.replace('sys_', '').replace('__x64_', '')
                clean_name = clean_name.replace('SYSCALL_DEFINE', '')
                
                if node.min_distance < float('inf'):
                    syscall_distances[clean_name] = node.min_distance
                    
        return syscall_distances
    
    def get_runtime_distance_map(self) -> Dict[int, float]:
        """
        Generate address -> distance mapping for KCOV instrumentation.
        Uses line numbers as proxy for addresses (real impl uses debug info).
        """
        addr_map = {}
        
        for bb_id, bb in self.basic_blocks.items():
            # Use line number as pseudo-address
            pseudo_addr = hash(f"{bb.file}:{bb.line_start}") & 0xFFFFFFFF
            addr_map[pseudo_addr] = bb.distance_to_target
            
        return addr_map
    
    def export_for_kcov(self, output_file: str):
        """Export distance map for KCOV module."""
        dist_map = self.get_runtime_distance_map()
        
        with open(output_file, 'w') as f:
            json.dump({
                'target_bbs': list(self.target_bbs),
                'bb_distances': {
                    bb_id: {
                        'file': bb.file,
                        'line': bb.line_start,
                        'distance': bb.distance_to_target,
                    }
                    for bb_id, bb in self.basic_blocks.items()
                },
                'func_distances': {
                    name: node.min_distance
                    for name, node in self.call_graph.items()
                },
            }, f, indent=2)
            
        print(f"[+] Exported distance map to {output_file}")


class RuntimeDistanceTracker:
    """
    Runtime distance tracking for fuzzing.
    Computes syscall/seed/template distances during execution.
    """
    
    def __init__(self, distance_map: Dict[int, float]):
        self.distance_map = distance_map
        self.current_seed_distances: List[float] = []
        self.template_distances: Dict[str, List[float]] = {}
        
    def track_syscall_execution(self, covered_addrs: List[int]) -> float:
        """
        Compute syscall distance from covered addresses.
        Returns minimum distance among covered BBs.
        """
        min_distance = float('inf')
        
        for addr in covered_addrs:
            if addr in self.distance_map:
                dist = self.distance_map[addr]
                if dist < min_distance:
                    min_distance = dist
                    
        return min_distance
    
    def compute_seed_distance(self, syscall_distances: List[float]) -> float:
        """
        Compute seed distance = min of syscall distances.
        """
        if not syscall_distances:
            return float('inf')
        return min(syscall_distances)
    
    def compute_template_distance(self, template_id: str,
                                   seed_distances: List[float]) -> float:
        """
        Compute template distance = avg of top-5 shortest seed distances.
        """
        if not seed_distances:
            return float('inf')
            
        sorted_dists = sorted(seed_distances)
        top_5 = sorted_dists[:5]
        
        return sum(top_5) / len(top_5)
    
    def update_template_stats(self, template_id: str, seed_distance: float):
        """Update template distance tracking."""
        if template_id not in self.template_distances:
            self.template_distances[template_id] = []
            
        self.template_distances[template_id].append(seed_distance)
        
        # Keep only most recent 100 seeds per template
        if len(self.template_distances[template_id]) > 100:
            self.template_distances[template_id] = \
                self.template_distances[template_id][-100:]


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SyzDirect Distance Calculator')
    parser.add_argument('--kernel', required=True, help='Path to kernel source')
    parser.add_argument('--target-file', required=True, help='Target source file')
    parser.add_argument('--target-line', type=int, required=True, help='Target line')
    parser.add_argument('--target-func', help='Target function name')
    parser.add_argument('--output', default='distances.json', help='Output file')
    
    args = parser.parse_args()
    
    calc = DistanceCalculator(args.kernel)
    info = calc.compute_distances(
        args.target_file,
        args.target_line,
        args.target_func
    )
    
    calc.export_for_kcov(args.output)
    
    print(f"\n[+] Distance calculation complete")
    print(f"    Syscall entry distances: {len(info.syscall_entry_distances)}")
