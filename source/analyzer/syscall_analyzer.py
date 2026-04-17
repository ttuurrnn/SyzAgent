#!/usr/bin/env python3
"""
SyzDirect Static Analyzer: Entry/Related Syscall Identification

Based on the SyzDirect paper:
- Entry syscall variant identification using resource/operation model + anchor function
- Dependent syscall inference using resource create/use relationships
- Argument condition refinement (code condition ↔ Syzlang condition matching)
"""

import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from source.common.target_spec import TargetSpec, load_target_spec
from source.common.template_bundle import save_template_bundle


TargetInfo = TargetSpec


@dataclass
class SyscallVariant:
    """Syscall variant with refined arguments"""
    name: str
    syzlang_name: str
    arguments: Dict[str, object] = field(default_factory=dict)
    constraints: List[str] = field(default_factory=list)
    resource_type: Optional[str] = None  # e.g., "fd", "sock", "file"
    operation_type: Optional[str] = None  # e.g., "read", "write", "ioctl"


@dataclass
class Template:
    """SyzDirect template: entry + related syscalls"""
    template_id: str
    entry_syscall: SyscallVariant
    related_syscalls: List[SyscallVariant] = field(default_factory=list)
    sequence_order: List[str] = field(default_factory=list)
    constraints: Dict[str, object] = field(default_factory=dict)


class SyscallAnalyzer:
    """
    Analyzes kernel source to identify entry and related syscalls
    for reaching a target code location.
    """
    
    # Common syscall entry patterns in kernel
    SYSCALL_PATTERNS = [
        r'SYSCALL_DEFINE\d+\s*\(\s*(\w+)',
        r'__SYSCALL\s*\(\s*\d+\s*,\s*sys_(\w+)',
        r'asmlinkage\s+.*\s+sys_(\w+)',
    ]
    
    # Resource type to syscall mapping (simplified)
    RESOURCE_SYSCALLS = {
        'fd': {
            'create': ['open', 'openat', 'socket', 'eventfd', 'timerfd_create', 'epoll_create'],
            'use': ['read', 'write', 'ioctl', 'close', 'fcntl', 'mmap'],
        },
        'sock': {
            'create': ['socket'],
            'configure': ['bind', 'listen', 'connect', 'setsockopt'],
            'use': ['send', 'recv', 'sendto', 'recvfrom', 'accept'],
        },
        'file': {
            'create': ['open', 'openat', 'creat'],
            'use': ['read', 'write', 'lseek', 'fstat'],
        },
        'mmap': {
            'create': ['mmap', 'mmap2'],
            'use': ['mprotect', 'munmap', 'msync'],
        },
    }
    
    def __init__(self, kernel_src: str, syzlang_dir: str = None):
        self.kernel_src = Path(kernel_src)
        self.syzlang_dir = Path(syzlang_dir) if syzlang_dir else None
        self.syscall_cache = {}
        self.callee_map = {}  # function -> set of callers
        
    def analyze_target(self, target: TargetInfo) -> List[Template]:
        """
        Main analysis entry point.
        Returns list of templates for fuzzing the target.
        """
        print(f"[*] Analyzing target: {target.target_id}")
        print(f"    File: {target.file_path}")
        print(f"    Function: {target.function or 'auto-detect'}")
        
        # Step 1: Find anchor functions (syscall entry points reaching target)
        anchor_functions = self._find_anchor_functions(target)
        print(f"[+] Found {len(anchor_functions)} anchor functions")
        
        # Step 2: Identify entry syscall variants
        entry_variants = self._identify_entry_variants(anchor_functions, target)
        if not entry_variants:
            entry_variants = self._variants_from_target_spec(target)
            if entry_variants:
                print(f"[+] Falling back to target spec syscall hints: {len(entry_variants)} entry variants")
        print(f"[+] Identified {len(entry_variants)} entry syscall variants")
        
        # Step 3: Infer dependent syscalls
        templates = []
        for entry in entry_variants:
            related = self._infer_related_syscalls(entry, target)
            entry_label = re.sub(r"[^0-9A-Za-z_]+", "_", entry.syzlang_name).strip("_") or entry.name
            template = Template(
                template_id=f"{target.target_id}_{entry_label}",
                entry_syscall=entry,
                related_syscalls=related,
                sequence_order=[s.name for s in related] + [entry.name],
            )
            templates.append(template)
            
        # Step 4: Refine argument constraints
        for template in templates:
            self._refine_constraints(template, target)
            
        print(f"[+] Generated {len(templates)} templates")
        return templates

    def _variants_from_target_spec(self, target: TargetInfo) -> List[SyscallVariant]:
        """Build entry variants from dataset-provided syscall hints when call-graph recovery fails."""
        entries: List[str] = []
        if target.entry_syscalls:
            entries.extend(target.entry_syscalls)
        elif target.sequence:
            entries.append(target.sequence[-1])

        variants: List[SyscallVariant] = []
        seen: Set[str] = set()
        for syscall_name in entries:
            if syscall_name in seen:
                continue
            seen.add(syscall_name)
            base_name, syzlang_name = self._normalize_syscall_name(syscall_name)
            variants.append(
                SyscallVariant(
                    name=base_name,
                    syzlang_name=syzlang_name,
                    resource_type=self._infer_resource_type(base_name),
                    operation_type=self._infer_operation_type(base_name),
                )
            )
        return variants

    def _normalize_syscall_name(self, syscall_name: str) -> tuple[str, str]:
        """Split a syzlang syscall variant into base syscall name and variant name."""
        if "$" in syscall_name:
            base_name = syscall_name.split("$", 1)[0]
            return base_name, syscall_name
        return syscall_name, self._map_to_syzlang(syscall_name)
    
    def _find_anchor_functions(self, target: TargetInfo) -> List[str]:
        """
        Find syscall entry points that can reach the target.
        Uses simplified call graph analysis.
        """
        target_file = self.kernel_src / target.file_path
        if not target_file.exists():
            print(f"[!] Target file not found: {target_file}")
            return []
            
        # Find function containing target line
        target_func = target.function
        if not target_func and target.line:
            target_func = self._find_function_at_line(target_file, target.line)
            
        if not target_func:
            print("[!] Could not determine target function")
            return []
            
        # Build reverse call graph and find syscall entries
        anchors = []
        visited = set()
        self._find_syscall_callers(target_func, visited, anchors, max_depth=10)
        
        return anchors
    
    def _find_function_at_line(self, file_path: Path, line: int) -> Optional[str]:
        """Find the function containing the given line number."""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                
            # Simple heuristic: find the nearest function definition above the line
            func_pattern = re.compile(r'^(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*{?\s*$')
            
            for i in range(line - 1, -1, -1):
                match = func_pattern.match(lines[i].strip())
                if match:
                    return match.group(1)
        except Exception as e:
            print(f"[!] Error finding function: {e}")
        return None
    
    def _find_syscall_callers(self, func: str, visited: Set[str], 
                              anchors: List[str], max_depth: int):
        """Recursively find syscall entry points calling this function."""
        if func in visited or max_depth <= 0:
            return
        visited.add(func)
        
        # Check if this is a syscall entry
        for pattern in self.SYSCALL_PATTERNS:
            if re.match(pattern.replace(r'(\w+)', func), f'sys_{func}'):
                anchors.append(func)
                return
                
        # Check if function matches known syscall patterns
        if func.startswith('sys_') or func.startswith('__x64_sys_'):
            anchors.append(func.replace('sys_', '').replace('__x64_', ''))
            return
            
        # Find callers and recurse
        callers = self._get_callers(func)
        for caller in callers:
            self._find_syscall_callers(caller, visited, anchors, max_depth - 1)
    
    def _get_callers(self, func: str) -> List[str]:
        """Get functions that call the given function (simplified grep-based)."""
        if func in self.callee_map:
            return self.callee_map[func]
            
        # Use grep to find callers (simplified approach)
        try:
            result = subprocess.run(
                ['grep', '-rn', f'{func}(', str(self.kernel_src)],
                capture_output=True, text=True, timeout=30
            )
            callers = set()
            func_pattern = re.compile(r'^(?:static\s+)?(?:\w+\s+)+(\w+)\s*\(')
            
            for line in result.stdout.split('\n'):
                if f':{func}(' in line:  # Skip definitions
                    continue
                # Extract calling function from context
                # This is simplified - real implementation would parse AST
                
            self.callee_map[func] = list(callers)
            return list(callers)
        except Exception:
            return []
    
    def _identify_entry_variants(self, anchors: List[str], 
                                  target: TargetInfo) -> List[SyscallVariant]:
        """
        Identify specific syscall variants that can reach target.
        Maps kernel functions to syzlang syscall definitions.
        """
        variants = []
        
        for anchor in anchors:
            # Map to syzlang name (simplified mapping)
            syzlang_name = self._map_to_syzlang(anchor)
            
            # Determine resource type from function context
            resource_type = self._infer_resource_type(anchor)
            
            variant = SyscallVariant(
                name=anchor,
                syzlang_name=syzlang_name,
                resource_type=resource_type,
                operation_type=self._infer_operation_type(anchor),
            )
            variants.append(variant)
            
        return variants
    
    def _map_to_syzlang(self, syscall: str) -> str:
        """Map kernel syscall name to syzlang definition name."""
        # Simplified mapping - real implementation parses syzlang files
        name = syscall.replace('sys_', '').replace('__x64_', '')
        return name
    
    def _infer_resource_type(self, func: str) -> Optional[str]:
        """Infer resource type from function name/context."""
        name = func.lower()
        if any(x in name for x in ['socket', 'sock', 'bind', 'listen']):
            return 'sock'
        if any(x in name for x in ['open', 'read', 'write', 'close']):
            return 'fd'
        if any(x in name for x in ['mmap', 'brk', 'mprotect']):
            return 'mmap'
        return None
    
    def _infer_operation_type(self, func: str) -> Optional[str]:
        """Infer operation type from function name."""
        name = func.lower()
        if 'read' in name:
            return 'read'
        if 'write' in name:
            return 'write'
        if 'ioctl' in name:
            return 'ioctl'
        if 'open' in name or 'create' in name:
            return 'create'
        return None
    
    def _infer_related_syscalls(self, entry: SyscallVariant, 
                                 target: TargetInfo) -> List[SyscallVariant]:
        """
        Infer related syscalls needed to set up context for entry syscall.
        Based on resource create/use relationships.
        """
        hinted_related = self._related_from_target_spec(entry, target)
        if hinted_related:
            return hinted_related

        related = []
        
        if not entry.resource_type:
            return related
            
        resource_info = self.RESOURCE_SYSCALLS.get(entry.resource_type, {})
        
        # Add create syscalls for required resources
        for create_syscall in resource_info.get('create', []):
            if create_syscall != entry.name:
                related.append(SyscallVariant(
                    name=create_syscall,
                    syzlang_name=self._map_to_syzlang(create_syscall),
                    resource_type=entry.resource_type,
                    operation_type='create',
                ))
                
        # Add configure syscalls if needed
        for config_syscall in resource_info.get('configure', []):
            related.append(SyscallVariant(
                name=config_syscall,
                syzlang_name=self._map_to_syzlang(config_syscall),
                resource_type=entry.resource_type,
                operation_type='configure',
            ))
            
        return related

    def _related_from_target_spec(self, entry: SyscallVariant, target: TargetInfo) -> List[SyscallVariant]:
        """Use dataset-provided syscall ordering when available."""
        related_names: List[str] = []
        if target.related_syscalls:
            related_names.extend(target.related_syscalls)
        elif target.sequence:
            for syscall_name in target.sequence:
                base_name, _ = self._normalize_syscall_name(syscall_name)
                if base_name == entry.name:
                    break
                related_names.append(syscall_name)

        related: List[SyscallVariant] = []
        seen: Set[str] = set()
        for syscall_name in related_names:
            base_name, syzlang_name = self._normalize_syscall_name(syscall_name)
            if base_name == entry.name or syzlang_name in seen:
                continue
            seen.add(syzlang_name)
            related.append(
                SyscallVariant(
                    name=base_name,
                    syzlang_name=syzlang_name,
                    resource_type=self._infer_resource_type(base_name),
                    operation_type=self._infer_operation_type(base_name),
                )
            )
        return related
    
    def _refine_constraints(self, template: Template, target: TargetInfo):
        """
        Refine argument constraints based on code conditions.
        Maps code literals/values to syzlang argument constraints.
        """
        # Analyze target file for condition patterns
        target_file = self.kernel_src / target.file_path
        if not target_file.exists():
            return
            
        try:
            with open(target_file, 'r') as f:
                content = f.read()
                
            # Extract condition patterns (simplified)
            # Real implementation uses AST analysis
            
            # Look for flag constants
            flag_pattern = re.compile(r'if\s*\(\s*(?:\w+)\s*&\s*(0x[0-9a-fA-F]+|\w+)')
            for match in flag_pattern.finditer(content):
                flag_val = match.group(1)
                template.constraints[f'flag_{flag_val}'] = flag_val
                
            # Look for ioctl command codes
            ioctl_pattern = re.compile(r'case\s+(0x[0-9a-fA-F]+|\w+):')
            for match in ioctl_pattern.finditer(content):
                cmd = match.group(1)
                if 'entry_syscall' in template.entry_syscall.name.lower():
                    template.entry_syscall.constraints.append(f'cmd={cmd}')
                    
        except Exception as e:
            print(f"[!] Error refining constraints: {e}")


def load_target(target_file: str) -> TargetInfo:
    """Load target specification from JSON file."""
    return load_target_spec(target_file)


def save_templates(templates: List[Template], output_file: str, target_id: str):
    """Save generated templates to JSON file."""
    template_dicts = [asdict(t) for t in templates]
    save_template_bundle(output_file, template_dicts, default_target_id=target_id)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SyzDirect Static Analyzer')
    parser.add_argument('--kernel', required=True, help='Path to kernel source')
    parser.add_argument('--target', required=True, help='Target specification JSON')
    parser.add_argument('--output', default='templates.json', help='Output templates file')
    parser.add_argument('--syzlang', help='Path to syzlang descriptions')
    
    args = parser.parse_args()
    
    target = load_target(args.target)
    analyzer = SyscallAnalyzer(args.kernel, args.syzlang)
    templates = analyzer.analyze_target(target)
    save_templates(templates, args.output, target.target_id)
    
    print(f"\n[+] Templates saved to {args.output}")
