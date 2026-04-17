#!/usr/bin/env python3
"""
SyzDirect Object/Parameter Synthesis Agent (R2 Response)

Addresses R2 failures: "Difficult parameter/object generation"

Actions:
1. Build filesystem image corpus (ext4, btrfs, f2fs variants)
2. Structural argument space reduction
3. Object creation pipeline (image→mount→fd→ioctl)
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from source.common.template_bundle import template_list


@dataclass
class FsImageSpec:
    """Filesystem image specification"""
    fs_type: str
    size_mb: int
    features: List[str] = field(default_factory=list)
    mount_options: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class ObjectPipeline:
    """Pipeline for creating complex objects"""
    name: str
    steps: List[Dict]  # Each step: {syscall, args, output}
    final_resource: str
    resource_type: str


class ObjectSynthesisAgent:
    """
    Agent for synthesizing complex objects and parameters.
    Addresses R2 failures from SyzDirect.
    """
    
    # Supported filesystem types
    FS_TYPES = ['ext4', 'ext3', 'ext2', 'btrfs', 'f2fs', 'xfs', 'minix', 'vfat']
    
    # Common filesystem features/variants
    FS_FEATURES = {
        'ext4': [
            ['metadata_csum', 'dir_index'],
            ['journal'],
            ['extent'],
            ['flex_bg'],
        ],
        'btrfs': [
            ['compress=zlib'],
            ['compress=lzo'],
            ['space_cache'],
        ],
        'f2fs': [
            ['compression'],
            ['extra_attr'],
        ],
    }
    
    # Object creation pipelines
    OBJECT_PIPELINES = {
        'mounted_fs': ObjectPipeline(
            name='mounted_fs',
            steps=[
                {'syscall': 'openat', 'args': {'path': '/dev/loop0'}, 'output': 'loop_fd'},
                {'syscall': 'ioctl', 'args': {'fd': 'loop_fd', 'cmd': 'LOOP_SET_FD'}, 'output': None},
                {'syscall': 'mount', 'args': {'source': '/dev/loop0', 'target': '/mnt/test'}, 'output': None},
            ],
            final_resource='mounted_fs',
            resource_type='mount',
        ),
        'device_fd': ObjectPipeline(
            name='device_fd',
            steps=[
                {'syscall': 'openat', 'args': {'path': '/dev/null'}, 'output': 'dev_fd'},
            ],
            final_resource='dev_fd',
            resource_type='fd',
        ),
        'memfd': ObjectPipeline(
            name='memfd',
            steps=[
                {'syscall': 'memfd_create', 'args': {'name': 'test'}, 'output': 'mem_fd'},
                {'syscall': 'ftruncate', 'args': {'fd': 'mem_fd', 'size': 4096}, 'output': None},
            ],
            final_resource='mem_fd',
            resource_type='fd',
        ),
        'userfaultfd': ObjectPipeline(
            name='userfaultfd',
            steps=[
                {'syscall': 'userfaultfd', 'args': {'flags': 0}, 'output': 'uffd'},
                {'syscall': 'ioctl', 'args': {'fd': 'uffd', 'cmd': 'UFFDIO_API'}, 'output': None},
            ],
            final_resource='uffd',
            resource_type='fd',
        ),
    }
    
    # Common argument ranges for syscalls
    ARG_RANGES = {
        'size': [(1, 4096), (4096, 65536), (65536, 1048576)],
        'offset': [(0, 0), (0, 4096), (4096, 65536)],
        'flags': 'bitfield',
        'mode': [(0o644, 0o644), (0o755, 0o755), (0o777, 0o777)],
        'count': [(1, 1), (1, 100), (100, 1000)],
    }
    
    def __init__(self, triage_result: Dict, template_data: Dict,
                 image_dir: str = '/work/images'):
        self.triage_result = triage_result
        self.template_data = template_data
        self.image_dir = Path(image_dir)
        self.image_dir.mkdir(parents=True, exist_ok=True)
        
    def analyze_and_synthesize(self) -> Dict:
        """
        Analyze failures and synthesize required objects.
        
        Returns:
            Dictionary with synthesized resources and enhanced templates
        """
        result = {
            'fs_images': [],
            'object_pipelines': [],
            'enhanced_templates': [],
            'argument_refinements': [],
        }
        
        # Check if filesystem images are needed
        if self._needs_fs_images():
            result['fs_images'] = self._generate_fs_image_specs()
            
        # Check for object pipeline needs
        needed_pipelines = self._identify_needed_pipelines()
        result['object_pipelines'] = needed_pipelines
        
        # Generate argument refinements based on error patterns
        result['argument_refinements'] = self._generate_arg_refinements()
        
        # Create enhanced templates with object setup
        result['enhanced_templates'] = self._create_enhanced_templates(
            needed_pipelines
        )
        
        return result
    
    def _needs_fs_images(self) -> bool:
        """Check if filesystem images are needed."""
        evidence = self.triage_result.get('evidence', [])
        
        fs_keywords = ['mount', 'filesystem', 'fs_image', 'loop', 'mkfs']
        for item in evidence:
            if any(kw in item.lower() for kw in fs_keywords):
                return True
                
        # Check templates for fs-related syscalls
        for template in template_list(self.template_data):
            entry = template.get('entry_syscall', {}).get('name', '')
            if entry in ['mount', 'umount', 'statfs', 'fstatfs']:
                return True
                
        return False
    
    def _generate_fs_image_specs(self) -> List[FsImageSpec]:
        """Generate filesystem image specifications."""
        specs = []
        
        # Generate minimal images for common filesystems
        for fs_type in ['ext4', 'btrfs', 'f2fs']:
            # Base minimal image
            specs.append(FsImageSpec(
                fs_type=fs_type,
                size_mb=16,
                features=[],
                mount_options=[],
                metadata={'variant': 'minimal'},
            ))
            
            # Variant with features if available
            features = self.FS_FEATURES.get(fs_type, [])
            for i, feature_set in enumerate(features[:2]):  # Limit variants
                specs.append(FsImageSpec(
                    fs_type=fs_type,
                    size_mb=32,
                    features=feature_set,
                    mount_options=[],
                    metadata={'variant': f'features_{i}'},
                ))
                
        return specs
    
    def _identify_needed_pipelines(self) -> List[Dict]:
        """Identify which object pipelines are needed."""
        needed = []
        
        # Analyze templates for resource requirements
        for template in template_list(self.template_data):
            entry = template.get('entry_syscall', {})
            entry_name = entry.get('name', '')
            resource_type = entry.get('resource_type')
            
            # Check if entry needs complex object
            if entry_name in ['ioctl'] and resource_type == 'fd':
                # May need device fd or special fd
                needed.append({
                    'pipeline': 'device_fd',
                    'for_syscall': entry_name,
                    'template_id': template.get('template_id'),
                })
                
            if 'mount' in entry_name or 'fs' in entry_name.lower():
                needed.append({
                    'pipeline': 'mounted_fs',
                    'for_syscall': entry_name,
                    'template_id': template.get('template_id'),
                })
                
            if 'userfault' in entry_name.lower():
                needed.append({
                    'pipeline': 'userfaultfd',
                    'for_syscall': entry_name,
                    'template_id': template.get('template_id'),
                })
                
        return needed
    
    def _generate_arg_refinements(self) -> List[Dict]:
        """Generate argument refinements based on error patterns."""
        refinements = []
        
        error_analysis = self.triage_result.get('error_analysis', {})
        
        # High EINVAL suggests invalid argument values
        if error_analysis.get('einval_rate', 0) > 0.3:
            refinements.append({
                'type': 'range_restriction',
                'description': 'Restrict integer arguments to small valid ranges',
                'rules': [
                    {'arg_type': 'size', 'range': (1, 4096)},
                    {'arg_type': 'count', 'range': (1, 16)},
                    {'arg_type': 'offset', 'range': (0, 4096)},
                ],
            })
            
        # High EFAULT suggests pointer/buffer issues
        if error_analysis.get('efault_rate', 0) > 0.2:
            refinements.append({
                'type': 'buffer_alignment',
                'description': 'Ensure buffers are properly aligned and sized',
                'rules': [
                    {'arg_type': 'buffer', 'min_size': 4096},
                    {'arg_type': 'pointer', 'alignment': 8},
                ],
            })
            
        return refinements
    
    def _create_enhanced_templates(self, pipelines: List[Dict]) -> List[Dict]:
        """Create enhanced templates with object setup pipelines."""
        enhanced = []
        
        for pipeline_req in pipelines:
            template_id = pipeline_req.get('template_id')
            pipeline_name = pipeline_req.get('pipeline')
            
            # Find original template
            original = None
            for t in template_list(self.template_data):
                if t.get('template_id') == template_id:
                    original = t
                    break
                    
            if not original:
                continue
                
            # Get pipeline definition
            pipeline = self.OBJECT_PIPELINES.get(pipeline_name)
            if not pipeline:
                continue
                
            # Create enhanced template
            import copy
            enhanced_template = copy.deepcopy(original)
            enhanced_template['template_id'] = f"{template_id}_with_{pipeline_name}"
            
            # Add pipeline steps as prefix syscalls
            prefix_syscalls = []
            for step in pipeline.steps:
                prefix_syscalls.append({
                    'name': step['syscall'],
                    'syzlang_name': step['syscall'],
                    'arguments': step.get('args', {}),
                    'return_resource': step.get('output'),
                    'operation_type': 'setup',
                })
                
            # Prepend to related syscalls
            enhanced_template['related_syscalls'] = (
                prefix_syscalls + enhanced_template.get('related_syscalls', [])
            )
            
            # Update sequence
            prefix_names = [s['name'] for s in prefix_syscalls]
            enhanced_template['sequence_order'] = (
                prefix_names + enhanced_template.get('sequence_order', [])
            )
            
            enhanced.append(enhanced_template)
            
        return enhanced
    
    def generate_fs_images(self) -> List[str]:
        """
        Actually generate filesystem images (requires root).
        Returns list of created image paths.
        """
        created = []
        specs = self._generate_fs_image_specs()
        
        for spec in specs:
            image_path = self.image_dir / f"{spec.fs_type}_{spec.metadata.get('variant', 'base')}.img"
            
            if image_path.exists():
                created.append(str(image_path))
                continue
                
            try:
                # Create empty file
                size_bytes = spec.size_mb * 1024 * 1024
                subprocess.run(
                    ['dd', 'if=/dev/zero', f'of={image_path}', 
                     'bs=1M', f'count={spec.size_mb}'],
                    check=True, capture_output=True
                )
                
                # Format with filesystem
                mkfs_cmd = [f'mkfs.{spec.fs_type}']
                if spec.features:
                    for feat in spec.features:
                        mkfs_cmd.extend(['-O', feat])
                mkfs_cmd.append(str(image_path))
                
                subprocess.run(mkfs_cmd, check=True, capture_output=True)
                
                created.append(str(image_path))
                print(f"[+] Created {image_path}")
                
            except Exception as e:
                print(f"[!] Failed to create {image_path}: {e}")
                
        return created


def synthesize_objects(triage_file: str, template_file: str, 
                       output_file: str, image_dir: str = '/work/images'):
    """Main entry point for object synthesis."""
    with open(triage_file, 'r') as f:
        triage_result = json.load(f)
        
    with open(template_file, 'r') as f:
        template_data = json.load(f)
        
    agent = ObjectSynthesisAgent(triage_result, template_data, image_dir)
    result = agent.analyze_and_synthesize()
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
        
    print(f"[+] Synthesis complete")
    print(f"    FS images: {len(result['fs_images'])}")
    print(f"    Pipelines: {len(result['object_pipelines'])}")
    print(f"    Enhanced templates: {len(result['enhanced_templates'])}")
    print(f"    Arg refinements: {len(result['argument_refinements'])}")
    
    return result


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Object/Parameter Synthesis Agent')
    parser.add_argument('--triage', required=True, help='Triage result JSON')
    parser.add_argument('--templates', required=True, help='Template JSON file')
    parser.add_argument('--output', default='synthesis_result.json', help='Output file')
    parser.add_argument('--image-dir', default='/work/images', help='Image output directory')
    parser.add_argument('--generate-images', action='store_true', help='Actually create FS images')
    
    args = parser.parse_args()
    
    result = synthesize_objects(args.triage, args.templates, args.output, args.image_dir)
    
    if args.generate_images:
        with open(args.triage, 'r') as f:
            triage = json.load(f)
        with open(args.templates, 'r') as f:
            templates = json.load(f)
            
        agent = ObjectSynthesisAgent(triage, templates, args.image_dir)
        images = agent.generate_fs_images()
        print(f"[+] Created {len(images)} filesystem images")
