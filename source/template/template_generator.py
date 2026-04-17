#!/usr/bin/env python3
"""
SyzDirect Template Generator

Generates fuzzing templates from analysis results.
Templates combine entry syscalls with related syscalls and refined arguments.
"""

import json
import math
import random
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from source.common.template_bundle import normalize_template_bundle, sanitize_json_numbers, template_list


@dataclass
class ArgumentSpec:
    """Specification for a syscall argument"""
    name: str
    type: str
    constraints: List[str] = field(default_factory=list)
    values: List[Any] = field(default_factory=list)
    resource_ref: Optional[str] = None  # Reference to resource from another syscall


@dataclass
class SyscallSpec:
    """Complete specification for a syscall in template"""
    name: str
    syzlang_name: str
    arguments: List[ArgumentSpec] = field(default_factory=list)
    return_resource: Optional[str] = None  # Resource this syscall creates
    distance: float = float('inf')


@dataclass
class FuzzTemplate:
    """Complete fuzzing template for SyzDirect"""
    template_id: str
    target_id: str
    
    # Syscall sequence
    entry_syscall: SyscallSpec
    related_syscalls: List[SyscallSpec] = field(default_factory=list)
    
    # Execution order
    sequence: List[str] = field(default_factory=list)
    
    # Template-level constraints
    constraints: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    estimated_distance: float = float('inf')
    priority: float = 0.0
    
    def to_syzlang_program(self) -> str:
        """Generate syzlang program from template."""
        lines = []
        
        # Generate related syscalls first (create resources)
        for syscall in self.related_syscalls:
            line = self._syscall_to_syzlang(syscall)
            lines.append(line)
            
        # Generate entry syscall
        line = self._syscall_to_syzlang(self.entry_syscall)
        lines.append(line)
        
        return '\n'.join(lines)
    
    def _syscall_to_syzlang(self, syscall: SyscallSpec) -> str:
        """Convert syscall spec to syzlang format."""
        args = []
        for arg in syscall.arguments:
            if arg.resource_ref:
                args.append(f'<{arg.resource_ref}>')
            elif arg.values:
                args.append(str(arg.values[0]))
            else:
                args.append('0x0')
                
        args_str = ', '.join(args)
        
        if syscall.return_resource:
            return f'{syscall.return_resource} = {syscall.syzlang_name}({args_str})'
        else:
            return f'{syscall.syzlang_name}({args_str})'


class TemplateGenerator:
    """
    Generates fuzzing templates from static analysis results.
    """
    
    # Syzlang type mappings
    RESOURCE_TYPES = {
        'fd': 'fd',
        'sock': 'sock',
        'pid': 'pid',
        'uid': 'uid',
        'gid': 'gid',
    }
    
    # Common syscall signatures (simplified)
    SYSCALL_SIGNATURES = {
        'open': {
            'args': [
                ('pathname', 'ptr[in, filename]'),
                ('flags', 'flags[open_flags]'),
                ('mode', 'flags[open_mode]'),
            ],
            'return': 'fd',
        },
        'openat': {
            'args': [
                ('dirfd', 'fd'),
                ('pathname', 'ptr[in, filename]'),
                ('flags', 'flags[open_flags]'),
                ('mode', 'flags[open_mode]'),
            ],
            'return': 'fd',
        },
        'socket': {
            'args': [
                ('domain', 'flags[socket_domain]'),
                ('type', 'flags[socket_type]'),
                ('protocol', 'int32'),
            ],
            'return': 'sock',
        },
        'read': {
            'args': [
                ('fd', 'fd'),
                ('buf', 'ptr[out, array[int8]]'),
                ('count', 'len[buf]'),
            ],
            'return': None,
        },
        'write': {
            'args': [
                ('fd', 'fd'),
                ('buf', 'ptr[in, array[int8]]'),
                ('count', 'len[buf]'),
            ],
            'return': None,
        },
        'ioctl': {
            'args': [
                ('fd', 'fd'),
                ('cmd', 'intptr'),
                ('arg', 'intptr'),
            ],
            'return': None,
        },
        'close': {
            'args': [
                ('fd', 'fd'),
            ],
            'return': None,
        },
        'mmap': {
            'args': [
                ('addr', 'vma'),
                ('length', 'len[addr]'),
                ('prot', 'flags[mmap_prot]'),
                ('flags', 'flags[mmap_flags]'),
                ('fd', 'fd'),
                ('offset', 'fileoff'),
            ],
            'return': 'vma',
        },
        'bind': {
            'args': [
                ('sockfd', 'sock'),
                ('addr', 'ptr[in, sockaddr]'),
                ('addrlen', 'len[addr]'),
            ],
            'return': None,
        },
        'listen': {
            'args': [
                ('sockfd', 'sock'),
                ('backlog', 'int32'),
            ],
            'return': None,
        },
        'setsockopt': {
            'args': [
                ('sockfd', 'sock'),
                ('level', 'int32'),
                ('optname', 'int32'),
                ('optval', 'ptr[in, array[int8]]'),
                ('optlen', 'len[optval]'),
            ],
            'return': None,
        },
    }
    
    def __init__(self, analysis_results: Any, distance_info: Dict = None):
        """
        Initialize generator with analysis results.
        
        Args:
            analysis_results: Output from syscall_analyzer
            distance_info: Output from distance_calculator
        """
        self.analysis = analysis_results
        self.distances = distance_info or {}
        self.resource_counter = 0
        
    def generate_templates(self) -> List[FuzzTemplate]:
        """Generate all templates from analysis results."""
        templates = []
        
        for template_data in template_list(self.analysis):
            template = self._create_template(template_data)
            if template:
                templates.append(template)
                
        # Sort by estimated distance (closer first)
        templates.sort(key=lambda t: t.estimated_distance)
        
        # Assign priorities
        for i, template in enumerate(templates):
            template.priority = 1.0 / (i + 1)
            
        return templates
    
    def _create_template(self, data: Dict) -> Optional[FuzzTemplate]:
        """Create a single template from analysis data."""
        try:
            entry_data = data.get('entry_syscall', {})
            entry_syscall = self._create_syscall_spec(entry_data)
            
            related_syscalls = []
            for rel_data in data.get('related_syscalls', []):
                rel_spec = self._create_syscall_spec(rel_data)
                related_syscalls.append(rel_spec)
                
            # Build sequence (related first, then entry)
            sequence = [s.name for s in related_syscalls] + [entry_syscall.name]
            
            # Estimate distance
            entry_name = entry_syscall.name
            estimated_dist = self.distances.get('syscall_entry_distances', {}).get(
                entry_name, float('inf')
            )
            
            template = FuzzTemplate(
                template_id=data.get('template_id', f'template_{id(data)}'),
                target_id=data.get('target_id', 'unknown'),
                entry_syscall=entry_syscall,
                related_syscalls=related_syscalls,
                sequence=sequence,
                constraints=data.get('constraints', {}),
                estimated_distance=estimated_dist,
            )
            
            # Link resources between syscalls
            self._link_resources(template)
            
            return template
            
        except Exception as e:
            print(f"[!] Error creating template: {e}")
            return None
    
    def _create_syscall_spec(self, data: Dict) -> SyscallSpec:
        """Create syscall specification from data."""
        name = data.get('name', 'unknown')
        syzlang_name = data.get('syzlang_name', name)
        
        # Get signature info
        sig = self.SYSCALL_SIGNATURES.get(name, {'args': [], 'return': None})
        
        arguments = []
        for arg_name, arg_type in sig.get('args', []):
            arg_spec = ArgumentSpec(
                name=arg_name,
                type=arg_type,
                constraints=data.get('constraints', []),
            )
            arguments.append(arg_spec)
            
        return SyscallSpec(
            name=name,
            syzlang_name=syzlang_name,
            arguments=arguments,
            return_resource=sig.get('return'),
        )
    
    def _link_resources(self, template: FuzzTemplate):
        """Link resource dependencies between syscalls."""
        resources = {}  # resource_type -> variable_name
        
        # Process related syscalls first (they create resources)
        for syscall in template.related_syscalls:
            if syscall.return_resource:
                self.resource_counter += 1
                var_name = f'r{self.resource_counter}'
                resources[syscall.return_resource] = var_name
                syscall.return_resource = var_name
                
        # Link entry syscall arguments to resources
        for arg in template.entry_syscall.arguments:
            if arg.type in self.RESOURCE_TYPES:
                res_type = self.RESOURCE_TYPES[arg.type]
                if res_type in resources:
                    arg.resource_ref = resources[res_type]
    
    def export_templates(self, templates: List[FuzzTemplate], output_dir: str):
        """Export templates to files."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Export JSON format
        templates_data = [asdict(t) for t in templates]
        bundle = normalize_template_bundle(
            templates_data,
            default_target_id=self.analysis.get("target_id", "unknown") if isinstance(self.analysis, dict) else "unknown",
        )
        with open(output_path / 'templates.json', 'w') as f:
            json.dump(sanitize_json_numbers(bundle), f, indent=2, allow_nan=False)
            
        # Export syzlang programs
        for template in templates:
            prog = template.to_syzlang_program()
            prog_file = output_path / f'{template.template_id}.syz'
            with open(prog_file, 'w') as f:
                f.write(prog)
                
        print(f"[+] Exported {len(templates)} templates to {output_dir}")

    def export_legacy_artifacts(
        self,
        templates: List[FuzzTemplate],
        callfile_output: str,
        program_output: str,
    ):
        program_path = Path(program_output)
        program_path.mkdir(parents=True, exist_ok=True)

        callfile_entries = []
        for template in templates:
            prog = template.to_syzlang_program()
            prog_file = program_path / f'{template.template_id}.syz'
            with open(prog_file, 'w') as f:
                f.write(prog)
            related_names = []
            seen_related = set()
            for syscall in template.related_syscalls:
                name = syscall.syzlang_name or syscall.name
                if name and name not in seen_related:
                    seen_related.add(name)
                    related_names.append(name)
            callfile_entries.append(
                {
                    "Target": template.entry_syscall.syzlang_name or template.entry_syscall.name,
                    "Relate": related_names,
                }
            )

        with open(callfile_output, 'w') as f:
            json.dump(sanitize_json_numbers(callfile_entries), f, indent=2, allow_nan=False)

        print(f"[+] Exported legacy callfile to {callfile_output}")
        print(f"[+] Exported {len(templates)} template programs to {program_output}")


class TemplateScheduler:
    """
    Schedules template selection based on distance feedback.
    Uses power scheduling similar to AFLGo.
    """
    
    def __init__(self, templates: List[FuzzTemplate], cooling_schedule: str = 'exp'):
        self.templates = templates
        self.cooling_schedule = cooling_schedule
        self.temperature = 1.0
        self.min_temperature = 0.05
        self.cooling_rate = 0.99
        
        # Template statistics
        self.template_stats = {
            t.template_id: {
                'executions': 0,
                'best_distance': t.estimated_distance,
                'improvements': 0,
                'last_improvement': 0,
            }
            for t in templates
        }
        
    def select_template(self, iteration: int) -> FuzzTemplate:
        """
        Select next template to use based on distance and exploration.
        
        Uses annealing-based selection:
        - High temperature: more exploration (random selection)
        - Low temperature: more exploitation (prefer low distance)
        """
        self._update_temperature(iteration)
        
        if random.random() < self.temperature:
            # Exploration: random selection
            return random.choice(self.templates)
        else:
            # Exploitation: select based on distance
            return self._select_by_distance()
    
    def _select_by_distance(self) -> FuzzTemplate:
        """Select template with best distance using weighted sampling."""
        # Compute weights (inverse of distance)
        weights = []
        for t in self.templates:
            stats = self.template_stats[t.template_id]
            dist = stats['best_distance']
            if dist == float('inf'):
                weight = 0.01
            else:
                weight = 1.0 / (dist + 1)
            weights.append(weight)
            
        total = sum(weights)
        if total == 0:
            return random.choice(self.templates)
            
        # Weighted random selection
        r = random.random() * total
        cumsum = 0
        for t, w in zip(self.templates, weights):
            cumsum += w
            if r <= cumsum:
                return t
                
        return self.templates[-1]
    
    def _update_temperature(self, iteration: int):
        """Update temperature based on cooling schedule."""
        if self.cooling_schedule == 'exp':
            self.temperature = max(
                self.min_temperature,
                self.temperature * self.cooling_rate
            )
        elif self.cooling_schedule == 'linear':
            self.temperature = max(
                self.min_temperature,
                1.0 - (iteration / 10000)
            )
    
    def update_stats(self, template_id: str, distance: float, iteration: int):
        """Update template statistics after execution."""
        if template_id not in self.template_stats:
            return
            
        stats = self.template_stats[template_id]
        stats['executions'] += 1
        
        if distance < stats['best_distance']:
            stats['improvements'] += 1
            stats['last_improvement'] = iteration
            stats['best_distance'] = distance


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SyzDirect Template Generator')
    parser.add_argument('--analysis', help='Analysis results JSON')
    parser.add_argument('--distances', help='Distance info JSON')
    parser.add_argument('--output', help='Output directory')
    parser.add_argument('--templates', help='Legacy template JSON input')
    parser.add_argument('--callfile-output', help='Legacy callfile JSON output')
    parser.add_argument('--program-output', help='Legacy syz program output directory')
    
    args = parser.parse_args()

    analysis_input = args.analysis or args.templates
    output_dir = args.output
    legacy_mode = bool(args.templates or args.callfile_output or args.program_output)

    if not analysis_input:
        parser.error('one of --analysis or --templates is required')
    if not legacy_mode and not output_dir:
        parser.error('--output is required unless using legacy export flags')
    if legacy_mode and (not args.callfile_output or not args.program_output):
        parser.error('--callfile-output and --program-output are required in legacy mode')
    
    # Load inputs
    with open(analysis_input, 'r') as f:
        analysis = json.load(f)
        
    distances = {}
    if args.distances:
        with open(args.distances, 'r') as f:
            distances = json.load(f)
            
    # Generate templates
    generator = TemplateGenerator(analysis, distances)
    templates = generator.generate_templates()
    
    # Export
    if output_dir:
        generator.export_templates(templates, output_dir)
    if legacy_mode:
        generator.export_legacy_artifacts(
            templates,
            args.callfile_output,
            args.program_output,
        )
    
    print(f"\n[+] Generated {len(templates)} templates")
