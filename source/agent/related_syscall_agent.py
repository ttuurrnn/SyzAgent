#!/usr/bin/env python3
"""
SyzDirect Related-Syscall Deepening Agent (R3 Response)

Addresses R3 failures: "Entry is correct but related syscall context is insufficient"

Actions:
1. Expand related syscall candidates (create→configure→use sequences)
2. Apply argument constraint refinement to related syscalls
3. Insert context builder syscalls (socket→setsockopt→bind pattern)
"""

import json
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from source.common.template_bundle import normalize_template_bundle, template_list


@dataclass
class ContextPattern:
    """Common syscall context pattern"""
    name: str
    sequence: List[str]
    resource_type: str
    description: str


@dataclass
class SyscallEnhancement:
    """Enhancement to apply to a syscall"""
    syscall_name: str
    action: str  # 'add_constraint' | 'add_predecessor' | 'add_successor'
    details: Dict


class RelatedSyscallAgent:
    """
    Agent for deepening related syscall analysis.
    Addresses R3 failures from SyzDirect.
    """
    
    # Common context patterns
    CONTEXT_PATTERNS = [
        ContextPattern(
            name='socket_setup',
            sequence=['socket', 'setsockopt', 'bind', 'listen'],
            resource_type='sock',
            description='Full socket initialization sequence',
        ),
        ContextPattern(
            name='socket_client',
            sequence=['socket', 'connect'],
            resource_type='sock',
            description='Client socket setup',
        ),
        ContextPattern(
            name='file_setup',
            sequence=['open', 'ftruncate', 'mmap'],
            resource_type='fd',
            description='File with mmap setup',
        ),
        ContextPattern(
            name='epoll_setup',
            sequence=['epoll_create', 'epoll_ctl'],
            resource_type='fd',
            description='Epoll event setup',
        ),
        ContextPattern(
            name='timerfd_setup',
            sequence=['timerfd_create', 'timerfd_settime'],
            resource_type='fd',
            description='Timer FD setup',
        ),
        ContextPattern(
            name='eventfd_setup',
            sequence=['eventfd', 'read', 'write'],
            resource_type='fd',
            description='Eventfd communication',
        ),
        ContextPattern(
            name='netlink_setup',
            sequence=['socket', 'bind', 'sendmsg'],
            resource_type='sock',
            description='Netlink socket setup',
        ),
        ContextPattern(
            name='ioctl_device',
            sequence=['open', 'ioctl'],
            resource_type='fd',
            description='Device ioctl pattern',
        ),
    ]
    
    # Syscall to common predecessors mapping
    SYSCALL_PREDECESSORS = {
        'read': ['open', 'openat', 'socket', 'pipe'],
        'write': ['open', 'openat', 'socket', 'pipe'],
        'ioctl': ['open', 'openat', 'socket'],
        'mmap': ['open', 'openat'],
        'send': ['socket', 'connect'],
        'sendmsg': ['socket', 'bind'],
        'sendmmsg': ['socket', 'bind'],
        'recv': ['socket', 'bind', 'listen', 'accept'],
        'recvmsg': ['socket', 'bind'],
        'sendto': ['socket'],
        'recvfrom': ['socket', 'bind'],
        'accept': ['socket', 'bind', 'listen'],
        'accept4': ['socket', 'bind', 'listen'],
        'bind': ['socket'],
        'listen': ['socket', 'bind'],
        'connect': ['socket'],
        'setsockopt': ['socket'],
        'getsockopt': ['socket'],
        'shutdown': ['socket'],
        'epoll_ctl': ['epoll_create', 'epoll_create1'],
        'epoll_wait': ['epoll_create', 'epoll_ctl'],
    }
    
    # Configuration syscalls that often need specific setup
    CONFIG_SYSCALLS = {
        'setsockopt': {
            'levels': ['SOL_SOCKET', 'SOL_TCP', 'SOL_IP', 'SOL_IPV6'],
            'common_opts': {
                'SOL_SOCKET': ['SO_REUSEADDR', 'SO_REUSEPORT', 'SO_KEEPALIVE'],
                'SOL_TCP': ['TCP_NODELAY', 'TCP_CORK'],
            },
        },
        'fcntl': {
            'commands': ['F_SETFL', 'F_SETFD', 'F_SETLK'],
            'flags': ['O_NONBLOCK', 'O_ASYNC', 'FD_CLOEXEC'],
        },
        'prctl': {
            'options': ['PR_SET_SECCOMP', 'PR_SET_NO_NEW_PRIVS'],
        },
    }
    
    def __init__(self, template_data: Dict, triage_result: Dict):
        self.template_data = template_data
        self.triage_result = triage_result
        self.enhancements: List[SyscallEnhancement] = []
        
    def analyze_and_enhance(self) -> List[Dict]:
        """
        Analyze templates and generate enhanced versions.
        
        Returns:
            List of enhanced template specifications
        """
        enhanced_templates = []
        
        for template in template_list(self.template_data):
            # Analyze current template
            entry = template.get('entry_syscall', {})
            related = template.get('related_syscalls', [])
            
            # Generate enhancements
            enhancements = self._generate_enhancements(entry, related)
            
            # Create enhanced templates (up to 3 variations)
            for i, enhancement_set in enumerate(enhancements[:3]):
                enhanced = self._apply_enhancements(template, enhancement_set)
                enhanced['template_id'] = f"{template.get('template_id')}_enhanced_{i}"
                enhanced_templates.append(enhanced)
                
        return enhanced_templates
    
    def _generate_enhancements(self, entry: Dict, 
                                related: List[Dict]) -> List[List[SyscallEnhancement]]:
        """Generate enhancement options for template."""
        all_enhancements = []
        
        # Strategy 1: Add missing predecessors
        pred_enhancements = self._check_missing_predecessors(entry, related)
        if pred_enhancements:
            all_enhancements.append(pred_enhancements)
            
        # Strategy 2: Add configuration syscalls
        config_enhancements = self._add_configuration_syscalls(entry, related)
        if config_enhancements:
            all_enhancements.append(config_enhancements)
            
        # Strategy 3: Apply context patterns
        pattern_enhancements = self._apply_context_patterns(entry, related)
        if pattern_enhancements:
            all_enhancements.append(pattern_enhancements)
            
        # Strategy 4: Add constraint refinements based on errors
        constraint_enhancements = self._add_constraint_refinements()
        if constraint_enhancements:
            all_enhancements.append(constraint_enhancements)
            
        return all_enhancements
    
    def _check_missing_predecessors(self, entry: Dict, 
                                     related: List[Dict]) -> List[SyscallEnhancement]:
        """Check for missing predecessor syscalls."""
        enhancements = []
        entry_name = entry.get('name', '')
        related_names = {r.get('name') for r in related}
        
        # Check if entry has known predecessors
        required_preds = self.SYSCALL_PREDECESSORS.get(entry_name, [])
        
        for pred in required_preds:
            if pred not in related_names:
                enhancements.append(SyscallEnhancement(
                    syscall_name=pred,
                    action='add_predecessor',
                    details={
                        'target': entry_name,
                        'reason': f'{pred} is commonly required before {entry_name}',
                    }
                ))
                
        return enhancements
    
    def _add_configuration_syscalls(self, entry: Dict,
                                     related: List[Dict]) -> List[SyscallEnhancement]:
        """Add configuration syscalls for resources."""
        enhancements = []
        
        # Check resource type
        resource_type = entry.get('resource_type')
        
        if resource_type == 'sock':
            # Add setsockopt if not present
            related_names = {r.get('name') for r in related}
            if 'setsockopt' not in related_names:
                enhancements.append(SyscallEnhancement(
                    syscall_name='setsockopt',
                    action='add_predecessor',
                    details={
                        'target': entry.get('name'),
                        'level': 'SOL_SOCKET',
                        'optname': 'SO_REUSEADDR',
                        'reason': 'Add socket configuration',
                    }
                ))
                
        return enhancements
    
    def _apply_context_patterns(self, entry: Dict,
                                 related: List[Dict]) -> List[SyscallEnhancement]:
        """Apply known context patterns."""
        enhancements = []
        resource_type = entry.get('resource_type')
        related_names = {r.get('name') for r in related}
        
        # Find matching patterns
        for pattern in self.CONTEXT_PATTERNS:
            if pattern.resource_type != resource_type:
                continue
                
            # Check if entry is in pattern sequence
            if entry.get('name') not in pattern.sequence:
                continue
                
            # Add missing syscalls from pattern
            for syscall in pattern.sequence:
                if syscall not in related_names and syscall != entry.get('name'):
                    enhancements.append(SyscallEnhancement(
                        syscall_name=syscall,
                        action='add_predecessor',
                        details={
                            'pattern': pattern.name,
                            'reason': pattern.description,
                        }
                    ))
                    
        return enhancements
    
    def _add_constraint_refinements(self) -> List[SyscallEnhancement]:
        """Add constraint refinements based on error analysis."""
        enhancements = []
        
        error_analysis = self.triage_result.get('error_analysis', {})
        
        # High EINVAL rate suggests parameter issues
        if error_analysis.get('einval_rate', 0) > 0.3:
            enhancements.append(SyscallEnhancement(
                syscall_name='*',  # Apply to all
                action='add_constraint',
                details={
                    'type': 'range_restriction',
                    'reason': 'High EINVAL rate detected',
                    'action': 'Restrict integer arguments to common valid ranges',
                }
            ))
            
        # High EPERM rate suggests permission/capability issues
        if error_analysis.get('eperm_rate', 0) > 0.2:
            enhancements.append(SyscallEnhancement(
                syscall_name='*',
                action='add_constraint',
                details={
                    'type': 'capability_setup',
                    'reason': 'High EPERM rate detected',
                    'action': 'Add capability-granting syscalls or use privileged mode',
                }
            ))
            
        return enhancements
    
    def _apply_enhancements(self, template: Dict,
                            enhancements: List[SyscallEnhancement]) -> Dict:
        """Apply enhancements to create new template."""
        import copy
        enhanced = copy.deepcopy(template)
        
        for enhancement in enhancements:
            if enhancement.action == 'add_predecessor':
                # Add syscall to related list
                new_syscall = {
                    'name': enhancement.syscall_name,
                    'syzlang_name': enhancement.syscall_name,
                    'operation_type': 'configure',
                    'constraints': [],
                }
                
                # Add specific constraints from details
                if 'level' in enhancement.details:
                    new_syscall['constraints'].append(
                        f"level={enhancement.details['level']}"
                    )
                if 'optname' in enhancement.details:
                    new_syscall['constraints'].append(
                        f"optname={enhancement.details['optname']}"
                    )
                    
                enhanced.setdefault('related_syscalls', []).insert(0, new_syscall)
                
            elif enhancement.action == 'add_constraint':
                # Add constraints to existing syscalls
                for syscall in enhanced.get('related_syscalls', []):
                    syscall.setdefault('constraints', []).append(
                        enhancement.details.get('action', 'unknown_constraint')
                    )
                    
        # Update sequence
        related_names = [s.get('name') for s in enhanced.get('related_syscalls', [])]
        entry_name = enhanced.get('entry_syscall', {}).get('name', '')
        enhanced['sequence_order'] = related_names + [entry_name]
        
        return enhanced
    
    def get_enhancement_summary(self) -> Dict:
        """Get summary of proposed enhancements."""
        summary = {
            'total_enhancements': len(self.enhancements),
            'by_action': {},
            'by_syscall': {},
        }
        
        for enh in self.enhancements:
            action = enh.action
            summary['by_action'][action] = summary['by_action'].get(action, 0) + 1
            
            syscall = enh.syscall_name
            summary['by_syscall'][syscall] = summary['by_syscall'].get(syscall, 0) + 1
            
        return summary


def enhance_templates(template_file: str, triage_file: str, output_file: str):
    """Main entry point for template enhancement."""
    with open(template_file, 'r') as f:
        template_data = json.load(f)
        
    with open(triage_file, 'r') as f:
        triage_result = json.load(f)
        
    agent = RelatedSyscallAgent(template_data, triage_result)
    enhanced = agent.analyze_and_enhance()
    
    output = {
        'original_template_count': len(template_list(template_data)),
        'enhanced_template_count': len(enhanced),
        'enhancement_summary': agent.get_enhancement_summary(),
    }
    output.update(normalize_template_bundle(enhanced))
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
        
    print(f"[+] Generated {len(enhanced)} enhanced templates")
    return enhanced


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Related-Syscall Deepening Agent')
    parser.add_argument('--templates', required=True, help='Template JSON file')
    parser.add_argument('--triage', required=True, help='Triage result JSON')
    parser.add_argument('--output', default='enhanced_templates.json', help='Output file')
    
    args = parser.parse_args()
    enhance_templates(args.templates, args.triage, args.output)
