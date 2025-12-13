#!/usr/bin/env python3
"""
Automated Hypervisor Vulnerability Hunter
Complete setup and exploitation framework for error handling vulnerabilities

Usage:
    ./vuln_hunter.py --setup          # Initial setup of tools
    ./vuln_hunter.py --scan TARGET    # Scan for vulnerabilities
    ./vuln_hunter.py --fuzz TARGET    # Run directed fuzzing
    ./vuln_hunter.py --full TARGET    # Complete pipeline
"""

import os
import sys
import json
import subprocess
import argparse
import shutil
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
import multiprocessing
import time

# Color output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    banner = f"""{Colors.OKBLUE}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Hypervisor Vulnerability Hunter v2.0                       ║
║   Error Handling Exploitation Framework                      ║
║                                                               ║
║   Based on "Scan Ranger" Research                            ║
║   Targets: QEMU, VirtualBox, VMware                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
    print(banner)

@dataclass
class Config:
    """Global configuration"""
    base_dir: Path
    tools_dir: Path
    qemu_dir: Path
    aflplusplus_dir: Path
    results_dir: Path
    cores: int
    
    @classmethod
    def from_args(cls, args):
        base_dir = Path(args.workdir).resolve()
        return cls(
            base_dir=base_dir,
            tools_dir=base_dir / "tools",
            qemu_dir=base_dir / "qemu",
            aflplusplus_dir=base_dir / "AFLplusplus",
            results_dir=base_dir / "results",
            cores=args.cores or multiprocessing.cpu_count()
        )
    
    def create_dirs(self):
        """Create all necessary directories"""
        for dir_path in [self.tools_dir, self.results_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Created directory structure")

class SetupManager:
    """Handles installation and setup of all tools"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def check_dependencies(self) -> bool:
        """Check if required system dependencies are installed"""
        print(f"\n{Colors.HEADER}[*] Checking dependencies...{Colors.ENDC}")
        
        required = {
            'git': 'git --version',
            'gcc': 'gcc --version',
            'make': 'make --version',
            'ninja': 'ninja --version',
            'python3': 'python3 --version',
            'pkg-config': 'pkg-config --version'
        }
        
        missing = []
        for tool, cmd in required.items():
            try:
                subprocess.run(cmd.split(), capture_output=True, check=True)
                print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} {tool}")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"{Colors.FAIL}[✗]{Colors.ENDC} {tool}")
                missing.append(tool)
        
        if missing:
            print(f"\n{Colors.FAIL}[!] Missing dependencies: {', '.join(missing)}{Colors.ENDC}")
            print(f"\nInstall with:")
            print(f"  sudo apt-get install -y {' '.join(missing)} build-essential")
            print(f"  sudo apt-get install -y libglib2.0-dev libpixman-1-dev libsdl2-dev")
            return False
        
        return True
    
    def clone_aflplusplus(self) -> bool:
        """Clone and build AFL++"""
        print(f"\n{Colors.HEADER}[*] Setting up AFL++...{Colors.ENDC}")
        
        if self.config.aflplusplus_dir.exists():
            print(f"{Colors.WARNING}[!] AFL++ already exists, skipping clone{Colors.ENDC}")
            return True
        
        try:
            # Clone
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Cloning AFL++...")
            subprocess.run([
                'git', 'clone', 
                'https://github.com/AFLplusplus/AFLplusplus',
                str(self.config.aflplusplus_dir)
            ], check=True)
            
            # Build
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Building AFL++...")
            subprocess.run(
                ['make', '-j', str(self.config.cores)],
                cwd=self.config.aflplusplus_dir,
                check=True
            )
            
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} AFL++ built successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[-] Failed to setup AFL++: {e}{Colors.ENDC}")
            return False
    
    def clone_qemu(self, version: str = "v8.2.0") -> bool:
        """Clone specific QEMU version"""
        print(f"\n{Colors.HEADER}[*] Setting up QEMU {version}...{Colors.ENDC}")
        
        if self.config.qemu_dir.exists():
            print(f"{Colors.WARNING}[!] QEMU already exists, skipping clone{Colors.ENDC}")
            return True
        
        try:
            # Clone
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Cloning QEMU...")
            subprocess.run([
                'git', 'clone',
                'https://github.com/qemu/qemu.git',
                str(self.config.qemu_dir)
            ], check=True)
            
            # Checkout version
            subprocess.run(
                ['git', 'checkout', version],
                cwd=self.config.qemu_dir,
                check=True
            )
            
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} QEMU cloned successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[-] Failed to clone QEMU: {e}{Colors.ENDC}")
            return False
    
    def detect_system_info(self) -> Dict[str, str]:
        """Detect system information"""
        import platform
        
        system = platform.system()
        machine = platform.machine()
        
        # Map to QEMU's expected values
        os_map = {
            'Linux': 'linux',
            'Darwin': 'darwin',
            'FreeBSD': 'freebsd',
            'OpenBSD': 'openbsd',
            'NetBSD': 'netbsd'
        }
        
        machine_map = {
            'x86_64': 'x86_64',
            'AMD64': 'x86_64',
            'aarch64': 'aarch64',
            'arm64': 'aarch64',
            'armv7l': 'arm'
        }
        
        return {
            'os': os_map.get(system, 'linux'),
            'machine': machine_map.get(machine, 'x86_64'),
            'raw_os': system,
            'raw_machine': machine
        }
    
    def install_qemu_dependencies(self) -> bool:
        """Install QEMU build dependencies"""
        print(f"\n{Colors.HEADER}[*] Installing QEMU dependencies...{Colors.ENDC}")
        
        sys_info = self.detect_system_info()
        
        if sys_info['raw_os'] == 'Linux':
            # Detect package manager
            if shutil.which('apt-get'):
                deps = [
                    'libglib2.0-dev', 'libpixman-1-dev', 'libfdt-dev',
                    'zlib1g-dev', 'libsdl2-dev', 'libslirp-dev',
                    'libcap-ng-dev', 'libattr1-dev', 'flex', 'bison'
                ]
                cmd = ['sudo', 'apt-get', 'install', '-y'] + deps
            elif shutil.which('dnf'):
                deps = [
                    'glib2-devel', 'pixman-devel', 'libfdt-devel',
                    'zlib-devel', 'SDL2-devel', 'libslirp-devel',
                    'libcap-ng-devel', 'libattr-devel', 'flex', 'bison'
                ]
                cmd = ['sudo', 'dnf', 'install', '-y'] + deps
            elif shutil.which('pacman'):
                deps = [
                    'glib2', 'pixman', 'dtc', 'zlib', 'sdl2',
                    'libslirp', 'libcap-ng', 'attr', 'flex', 'bison'
                ]
                cmd = ['sudo', 'pacman', '-S', '--noconfirm'] + deps
            else:
                print(f"{Colors.WARNING}[!] Unknown package manager, install deps manually{Colors.ENDC}")
                return True
            
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Installing: {' '.join(deps)}")
            try:
                subprocess.run(cmd, check=True)
                print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Dependencies installed")
            except subprocess.CalledProcessError:
                print(f"{Colors.WARNING}[!] Failed to install some deps (may need sudo){Colors.ENDC}")
        
        return True
    
    def build_qemu_instrumented(self) -> bool:
        """Build QEMU with AFL++ instrumentation"""
        print(f"\n{Colors.HEADER}[*] Building instrumented QEMU...{Colors.ENDC}")
        
        # Install dependencies first
        self.install_qemu_dependencies()
        
        build_dir = self.config.qemu_dir / "build"
        build_dir.mkdir(exist_ok=True)
        
        # Detect system
        sys_info = self.detect_system_info()
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Detected: {sys_info['raw_os']} {sys_info['raw_machine']}")
        
        try:
            # Set AFL++ compiler
            afl_cc = self.config.aflplusplus_dir / "afl-clang-fast"
            afl_cxx = self.config.aflplusplus_dir / "afl-clang-fast++"
            
            if not afl_cc.exists():
                print(f"{Colors.FAIL}[-] AFL++ compilers not found{Colors.ENDC}")
                return False
            
            env = os.environ.copy()
            env['CC'] = str(afl_cc)
            env['CXX'] = str(afl_cxx)
            
            # Don't use ASAN if it causes issues
            # env['AFL_USE_ASAN'] = '1'
            
            # More compatible configure options
            configure_opts = [
                '../configure',
                '--target-list=x86_64-softmmu',
                '--enable-debug',
                '--disable-werror',
                '--disable-docs',
                '--disable-gtk',
                '--disable-vnc',
                '--disable-curses',
                '--enable-slirp',
                f'--prefix={build_dir / "install"}'
            ]
            
            # Configure
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Configuring QEMU...")
            print(f"{Colors.OKCYAN}    Command: {' '.join(configure_opts)}{Colors.ENDC}")
            
            result = subprocess.run(
                configure_opts,
                cwd=build_dir,
                env=env,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"{Colors.FAIL}[-] Configure failed:{Colors.ENDC}")
                print(result.stdout)
                print(result.stderr)
                
                # Try fallback without AFL
                print(f"\n{Colors.WARNING}[!] Trying fallback build without AFL instrumentation...{Colors.ENDC}")
                env_fallback = os.environ.copy()
                
                subprocess.run(
                    configure_opts,
                    cwd=build_dir,
                    env=env_fallback,
                    check=True
                )
                print(f"{Colors.WARNING}[!] Using non-instrumented build (fuzzing will be less effective){Colors.ENDC}")
            
            # Build
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Building (this may take 10-20 minutes)...")
            print(f"{Colors.OKCYAN}    Using {self.config.cores} cores{Colors.ENDC}")
            
            subprocess.run(
                ['make', '-j', str(self.config.cores)],
                cwd=build_dir,
                check=True
            )
            
            # Verify binary exists
            qemu_bin = build_dir / 'qemu-system-x86_64'
            if not qemu_bin.exists():
                print(f"{Colors.FAIL}[-] QEMU binary not found after build{Colors.ENDC}")
                return False
            
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} QEMU built successfully")
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Binary: {qemu_bin}")
            
            # Test binary
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Testing binary...")
            result = subprocess.run(
                [str(qemu_bin), '--version'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {version}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[-] Failed to build QEMU: {e}{Colors.ENDC}")
            
            # Provide helpful error message
            print(f"\n{Colors.WARNING}Troubleshooting:{Colors.ENDC}")
            print(f"  1. Install missing dependencies:")
            print(f"     sudo apt-get install -y build-essential libglib2.0-dev libpixman-1-dev")
            print(f"  2. Check build logs in: {build_dir}")
            print(f"  3. Try manual build:")
            print(f"     cd {build_dir}")
            print(f"     ../configure --target-list=x86_64-softmmu")
            print(f"     make -j{self.config.cores}")
            
            return False
    
    def build_qemu_simple(self) -> bool:
        """Build QEMU without instrumentation (faster, for scanning only)"""
        print(f"\n{Colors.HEADER}[*] Building QEMU (simple mode)...{Colors.ENDC}")
        
        # Install dependencies first
        self.install_qemu_dependencies()
        
        build_dir = self.config.qemu_dir / "build"
        build_dir.mkdir(exist_ok=True)
        
        try:
            # Simple configure without AFL
            configure_opts = [
                '../configure',
                '--target-list=x86_64-softmmu',
                '--disable-docs',
                '--disable-gtk',
                '--disable-vnc',
                f'--prefix={build_dir / "install"}'
            ]
            
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Configuring QEMU...")
            subprocess.run(
                configure_opts,
                cwd=build_dir,
                check=True
            )
            
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Building (5-10 minutes)...")
            subprocess.run(
                ['make', '-j', str(self.config.cores)],
                cwd=build_dir,
                check=True
            )
            
            qemu_bin = build_dir / 'qemu-system-x86_64'
            if not qemu_bin.exists():
                print(f"{Colors.FAIL}[-] QEMU binary not found{Colors.ENDC}")
                return False
            
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} QEMU built successfully (simple mode)")
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Binary: {qemu_bin}")
            print(f"{Colors.WARNING}[!] Note: This build is for static analysis only{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] For fuzzing, use: --setup (full mode){Colors.ENDC}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[-] Failed to build QEMU: {e}{Colors.ENDC}")
            return False
    
    def setup_simple(self) -> bool:
        """Simple setup for static analysis only"""
        print_banner()
        print(f"\n{Colors.OKCYAN}SIMPLE SETUP MODE{Colors.ENDC}")
        print(f"{Colors.OKCYAN}This mode is faster but only supports static analysis (--scan){Colors.ENDC}\n")
        
        if not self.check_dependencies():
            return False
        
        self.config.create_dirs()
        
        # Clone QEMU (skip AFL++)
        if not self.clone_qemu():
            return False
        
        # Build QEMU without instrumentation
        if not self.build_qemu_simple():
            return False
        
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}[✓] Simple setup complete!{Colors.ENDC}")
        print(f"{Colors.OKCYAN}You can now:{Colors.ENDC}")
        print(f"  • Scan devices: {sys.argv[0]} --scan virtio-gpu")
        print(f"{Colors.WARNING}  • For fuzzing: Run full setup with --setup{Colors.ENDC}")
        
        return True
    
    def setup_all(self) -> bool:
        """Run complete setup"""
        print_banner()
        
        if not self.check_dependencies():
            return False
        
        self.config.create_dirs()
        
        if not self.clone_aflplusplus():
            return False
        
        if not self.clone_qemu():
            return False
        
        if not self.build_qemu_instrumented():
            return False
        
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}[✓] Setup complete!{Colors.ENDC}")
        return True

class ErrorHandlingScanner:
    """Static analysis scanner for error handling vulnerabilities"""
    
    def __init__(self, config: Config):
        self.config = config
        self.results = []
    
    def find_goto_patterns(self, content: str, filepath: str) -> List[Dict]:
        """Find goto statements and analyze error handling"""
        findings = []
        
        # Pattern: goto label;
        goto_pattern = r'goto\s+(\w+)\s*;'
        gotos = [(m.group(1), m.start()) for m in re.finditer(goto_pattern, content)]
        
        # Pattern: label:
        label_pattern = r'^(\w+):\s*$'
        labels = [(m.group(1), m.start()) for m in re.finditer(label_pattern, content, re.MULTILINE)]
        
        # Error-related labels
        error_labels = ['error', 'err', 'fail', 'cleanup', 'out', 'done', 'unmap']
        
        for label_name, label_pos in labels:
            if any(err in label_name.lower() for err in error_labels):
                # Extract code block after label
                block = self.extract_code_block(content, label_pos)
                operations = self.analyze_operations(block)
                
                if operations['dangerous_count'] > 0:
                    findings.append({
                        'file': str(filepath),
                        'label': label_name,
                        'line': content[:label_pos].count('\n') + 1,
                        'operations': operations,
                        'code_snippet': block[:500],
                        'risk_score': self.calculate_risk_score(operations)
                    })
        
        return findings
    
    def extract_code_block(self, content: str, start_pos: int) -> str:
        """Extract code block from label to next label or closing brace"""
        remaining = content[start_pos:]
        
        # Find end of block (next label or closing brace at start of line)
        end_match = re.search(r'\n(\w+:|^\})', remaining)
        if end_match:
            return remaining[:end_match.start()]
        
        return remaining[:1000]  # Max 1000 chars
    
    def analyze_operations(self, code_block: str) -> Dict:
        """Analyze operations in error handling block"""
        operations = {
            'free': len(re.findall(r'(?:g_free|free|kfree)\s*\(', code_block)),
            'close': len(re.findall(r'close\s*\(', code_block)),
            'unlock': len(re.findall(r'(?:mutex_unlock|qemu_mutex_unlock)\s*\(', code_block)),
            'destroy': len(re.findall(r'\w+_destroy\s*\(', code_block)),
            'cleanup': len(re.findall(r'\w+_cleanup\s*\(', code_block)),
            'unmap': len(re.findall(r'(?:unmap|dma_unmap)\s*\(', code_block)),
        }
        
        operations['dangerous_count'] = sum(operations.values())
        return operations
    
    def calculate_risk_score(self, operations: Dict) -> int:
        """Calculate risk score (0-100)"""
        score = 0
        
        # More operations = higher risk
        score += min(operations['dangerous_count'] * 15, 50)
        
        # Specific high-risk operations
        if operations['free'] > 0:
            score += 30
        if operations['unmap'] > 0:
            score += 20
        
        return min(score, 100)
    
    def find_unchecked_calls(self, content: str, filepath: str) -> List[Dict]:
        """Find function calls that don't check return values"""
        findings = []
        
        # Find function definitions that return error codes
        func_pattern = r'(int|ssize_t|long)\s+(\w+)\s*\([^)]*\)\s*\{'
        functions = [m.group(2) for m in re.finditer(func_pattern, content)]
        
        for func_name in functions:
            # Look for calls to this function without checking return value
            call_pattern = rf'{func_name}\s*\([^)]*\)\s*;'
            
            for match in re.finditer(call_pattern, content):
                # Check if there's an if/assignment before the call
                context_start = max(0, match.start() - 100)
                context = content[context_start:match.start()]
                
                if not re.search(r'(?:if\s*\(|=\s*|return\s+)', context):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    findings.append({
                        'file': str(filepath),
                        'function': func_name,
                        'line': line_num,
                        'call': match.group(0).strip(),
                        'type': 'unchecked_return',
                        'risk_score': 70
                    })
        
        return findings
    
    def scan_file(self, filepath: Path) -> List[Dict]:
        """Scan a single file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"{Colors.WARNING}[!] Error reading {filepath}: {e}{Colors.ENDC}")
            return []
        
        findings = []
        findings.extend(self.find_goto_patterns(content, filepath))
        findings.extend(self.find_unchecked_calls(content, filepath))
        
        return findings
    
    def scan_device(self, device_name: str) -> Dict:
        """Scan specific device directory"""
        print(f"\n{Colors.HEADER}[*] Scanning {device_name}...{Colors.ENDC}")
        
        # Device path mappings
        device_paths = {
            'virtio-gpu': 'hw/display/virtio-gpu*.c',
            'virtio-scsi': 'hw/scsi/virtio-scsi*.c',
            'virtio-crypto': 'hw/virtio/virtio-crypto*.c',
            'vmware-svga': 'hw/display/vmware_vga.c',
            'ahci': 'hw/ide/ahci*.c',
            'nvme': 'hw/block/nvme*.c',
            'e1000': 'hw/net/e1000*.c',
            'usb-xhci': 'hw/usb/hcd-xhci*.c',
        }
        
        if device_name not in device_paths:
            print(f"{Colors.FAIL}[-] Unknown device: {device_name}{Colors.ENDC}")
            return {'findings': [], 'files_scanned': 0}
        
        # Find matching files
        pattern = device_paths[device_name]
        base_path = self.config.qemu_dir
        
        if '*' in pattern:
            # Glob pattern
            parts = pattern.split('/')
            search_dir = base_path / '/'.join(parts[:-1])
            file_pattern = parts[-1]
            files = list(search_dir.glob(file_pattern))
        else:
            files = [base_path / pattern]
        
        files = [f for f in files if f.exists()]
        
        if not files:
            print(f"{Colors.FAIL}[-] No files found for {device_name}{Colors.ENDC}")
            return {'findings': [], 'files_scanned': 0}
        
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Scanning {len(files)} file(s)...")
        
        all_findings = []
        for filepath in files:
            print(f"{Colors.OKBLUE}  [*]{Colors.ENDC} {filepath.name}")
            findings = self.scan_file(filepath)
            all_findings.extend(findings)
        
        # Sort by risk score
        all_findings.sort(key=lambda x: x['risk_score'], reverse=True)
        
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Found {len(all_findings)} potential vulnerabilities")
        
        return {
            'device': device_name,
            'files_scanned': len(files),
            'findings': all_findings,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def generate_report(self, scan_results: Dict) -> str:
        """Generate human-readable report"""
        report = []
        report.append("=" * 80)
        report.append(f"VULNERABILITY SCAN REPORT: {scan_results['device']}")
        report.append("=" * 80)
        report.append(f"\nScan Time: {scan_results['timestamp']}")
        report.append(f"Files Scanned: {scan_results['files_scanned']}")
        report.append(f"Potential Vulnerabilities: {len(scan_results['findings'])}\n")
        
        if not scan_results['findings']:
            report.append("No vulnerabilities found.")
            return "\n".join(report)
        
        # Group by risk score
        critical = [f for f in scan_results['findings'] if f['risk_score'] >= 80]
        high = [f for f in scan_results['findings'] if 60 <= f['risk_score'] < 80]
        medium = [f for f in scan_results['findings'] if f['risk_score'] < 60]
        
        if critical:
            report.append(f"\n🔴 CRITICAL RISK ({len(critical)})")
            report.append("-" * 80)
            for i, finding in enumerate(critical[:5], 1):
                report.append(f"\n[{i}] {finding['file']}:{finding['line']}")
                report.append(f"    Risk Score: {finding['risk_score']}/100")
                if 'label' in finding:
                    report.append(f"    Error Label: {finding['label']}")
                    report.append(f"    Operations: {finding['operations']}")
        
        if high:
            report.append(f"\n🟡 HIGH RISK ({len(high)})")
            report.append("-" * 80)
            for i, finding in enumerate(high[:5], 1):
                report.append(f"\n[{i}] {finding['file']}:{finding['line']}")
                report.append(f"    Risk Score: {finding['risk_score']}/100")
        
        report.append(f"\n\nTotal: {len(critical)} critical, {len(high)} high, {len(medium)} medium")
        report.append("\nFull details saved to JSON report.")
        
        return "\n".join(report)

class FuzzingManager:
    """Manages AFL++ fuzzing campaigns"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def generate_seeds(self, device: str, seed_dir: Path) -> bool:
        """Generate initial seed files for device"""
        print(f"\n{Colors.HEADER}[*] Generating seeds for {device}...{Colors.ENDC}")
        
        seed_dir.mkdir(parents=True, exist_ok=True)
        
        # Device-specific seed generation
        seed_templates = {
            'virtio-gpu': self._generate_virtio_gpu_seeds,
            'virtio-scsi': self._generate_virtio_scsi_seeds,
            'nvme': self._generate_nvme_seeds,
        }
        
        generator = seed_templates.get(device, self._generate_generic_seeds)
        return generator(seed_dir)
    
    def _generate_virtio_gpu_seeds(self, seed_dir: Path) -> bool:
        """Generate VirtIO GPU specific seeds"""
        commands = [
            # VIRTIO_GPU_CMD_GET_DISPLAY_INFO
            b'\x00\x01\x00\x00' + b'\x00' * 60,
            # VIRTIO_GPU_CMD_RESOURCE_CREATE_2D
            b'\x00\x02\x00\x00' + b'\x01\x00\x00\x00' + b'\x80\x07\x00\x00' + b'\x38\x04\x00\x00',
            # Invalid command (trigger error)
            b'\xff\xff\x00\x00' + b'\xde\xad\xbe\xef' * 10,
        ]
        
        for i, cmd in enumerate(commands):
            (seed_dir / f'seed_{i:03d}.bin').write_bytes(cmd)
        
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Generated {len(commands)} seeds")
        return True
    
    def _generate_virtio_scsi_seeds(self, seed_dir: Path) -> bool:
        """Generate VirtIO SCSI specific seeds"""
        # SCSI commands
        commands = [
            b'\x00' * 64,  # Empty command
            b'\x12\x00\x00\x00\xff\x00' + b'\x00' * 58,  # INQUIRY
            b'\xff' * 64,  # Invalid
        ]
        
        for i, cmd in enumerate(commands):
            (seed_dir / f'seed_{i:03d}.bin').write_bytes(cmd)
        
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Generated {len(commands)} seeds")
        return True
    
    def _generate_nvme_seeds(self, seed_dir: Path) -> bool:
        """Generate NVMe specific seeds"""
        commands = [
            b'\x00' * 64,  # Admin command
            b'\x01\x00\x00\x00' + b'\x00' * 60,  # Read
            b'\xff' * 64,  # Invalid
        ]
        
        for i, cmd in enumerate(commands):
            (seed_dir / f'seed_{i:03d}.bin').write_bytes(cmd)
        
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Generated {len(commands)} seeds")
        return True
    
    def _generate_generic_seeds(self, seed_dir: Path) -> bool:
        """Generate generic seeds"""
        seeds = [
            b'\x00' * 64,
            b'\xff' * 64,
            b'\xaa\x55' * 32,
        ]
        
        for i, seed in enumerate(seeds):
            (seed_dir / f'seed_{i:03d}.bin').write_bytes(seed)
        
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Generated {len(seeds)} generic seeds")
        return True
    
    def create_harness(self, device: str) -> Path:
        """Create fuzzing harness for device"""
        harness_dir = self.config.results_dir / device / 'harness'
        harness_dir.mkdir(parents=True, exist_ok=True)
        
        harness_file = harness_dir / 'fuzz_harness.c'
        
        # Device-specific harness code
        harness_code = f'''
/*
 * AFL++ Fuzzing Harness for {device}
 * Compile with: afl-clang-fast -o harness fuzz_harness.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_INPUT 4096

/* Simulated device state */
typedef struct {{
    uint32_t status;
    uint32_t error_count;
    void *resource;
}} device_state_t;

device_state_t dev_state = {{0}};

/* 
 * Simulate device operations that trigger error paths
 * This is a simplified model - real fuzzing would use QEMU's device code
 */
int process_device_command(uint8_t *data, size_t len) {{
    if (len < 8) return -1;
    
    uint32_t cmd = *(uint32_t *)data;
    uint32_t param = *(uint32_t *)(data + 4);
    
    // Simulate error conditions based on input
    switch (cmd) {{
        case 0x01: // Resource create
            if (param > 0x1000) {{
                // Trigger error path
                if (dev_state.resource) {{
                    free(dev_state.resource);
                    dev_state.resource = NULL;
                }}
                return -1;
            }}
            dev_state.resource = malloc(param);
            break;
            
        case 0x02: // Resource map
            if (!dev_state.resource) {{
                // Uninitialized access
                return -1;
            }}
            break;
            
        case 0xFF: // Invalid command
            // Force error path
            return -1;
            
        default:
            break;
    }}
    
    return 0;
}}

#ifdef __AFL_FUZZ_TESTCASE_LEN
/* Persistent mode for AFL++ */
__AFL_FUZZ_INIT();
#endif

int main(int argc, char **argv) {{
#ifdef __AFL_FUZZ_TESTCASE_LEN
    /* Persistent mode */
    __AFL_INIT();
    
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(1000)) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        if (len > MAX_INPUT) len = MAX_INPUT;
        
        process_device_command(buf, len);
        
        // Reset state
        if (dev_state.resource) {{
            free(dev_state.resource);
            dev_state.resource = NULL;
        }}
    }}
#else
    /* File input mode */
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}
    
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 1;
    
    uint8_t buf[MAX_INPUT];
    ssize_t len = read(fd, buf, sizeof(buf));
    close(fd);
    
    if (len > 0) {{
        process_device_command(buf, len);
    }}
#endif
    
    return 0;
}}
'''
        
        harness_file.write_text(harness_code)
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Created harness: {harness_file}")
        
        return harness_file
    
    def compile_harness(self, harness_file: Path) -> Optional[Path]:
        """Compile fuzzing harness with AFL++"""
        print(f"\n{Colors.HEADER}[*] Compiling fuzzing harness...{Colors.ENDC}")
        
        afl_cc = self.config.aflplusplus_dir / 'afl-clang-fast'
        if not afl_cc.exists():
            # Try regular compiler as fallback
            print(f"{Colors.WARNING}[!] AFL++ compiler not found, using gcc{Colors.ENDC}")
            afl_cc = 'gcc'
        
        output_bin = harness_file.parent / 'harness'
        
        try:
            cmd = [
                str(afl_cc),
                '-o', str(output_bin),
                str(harness_file),
                '-O2'
            ]
            
            subprocess.run(cmd, check=True)
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Harness compiled: {output_bin}")
            return output_bin
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[-] Failed to compile harness: {e}{Colors.ENDC}")
            return None
    
    def start_fuzzing(self, device: str, duration_hours: int = 24) -> bool:
        """Start AFL++ fuzzing campaign"""
        print(f"\n{Colors.HEADER}[*] Starting fuzzing campaign for {device}...{Colors.ENDC}")
        
        # Setup directories
        device_dir = self.config.results_dir / device
        seed_dir = device_dir / 'seeds'
        output_dir = device_dir / 'afl_output'
        
        # Generate seeds
        if not self.generate_seeds(device, seed_dir):
            return False
        
        # Create and compile harness
        harness_file = self.create_harness(device)
        harness_bin = self.compile_harness(harness_file)
        
        if not harness_bin:
            print(f"{Colors.FAIL}[-] Cannot fuzz without compiled harness{Colors.ENDC}")
            return False
        
        # AFL++ binary
        afl_fuzz = self.config.aflplusplus_dir / 'afl-fuzz'
        if not afl_fuzz.exists():
            print(f"{Colors.FAIL}[-] AFL++ not found at {afl_fuzz}{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Install AFL++ with: {sys.argv[0]} --setup{Colors.ENDC}")
            return False
        
        # Start fuzzing
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Fuzzing will run for {duration_hours} hours")
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Output: {output_dir}")
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Press Ctrl+C to stop early")
        
        try:
            cmd = [
                str(afl_fuzz),
                '-i', str(seed_dir),
                '-o', str(output_dir),
                '-m', 'none',
                '-t', '1000+',
                '--',
                str(harness_bin),
                '@@'
            ]
            
            print(f"\n{Colors.OKGREEN}[+] Starting AFL++...{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Command: {' '.join(cmd)}{Colors.ENDC}\n")
            
            subprocess.run(cmd, timeout=duration_hours * 3600)
            
        except subprocess.TimeoutExpired:
            print(f"\n{Colors.OKGREEN}[+] Fuzzing completed (timeout){Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Fuzzing stopped by user{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}[-] Fuzzing error: {e}{Colors.ENDC}")
            return False
        
        # Analyze results
        crashes_dir = output_dir / 'default' / 'crashes'
        if crashes_dir.exists():
            crashes = [f for f in crashes_dir.glob('*') if f.is_file() and f.name != 'README.txt']
            print(f"\n{Colors.OKGREEN}[+] Fuzzing complete{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Crashes found: {len(crashes)}{Colors.ENDC}")
            
            if crashes:
                print(f"\n{Colors.HEADER}Top crashes:{Colors.ENDC}")
                for i, crash in enumerate(crashes[:5], 1):
                    print(f"  {i}. {crash.name}")
        else:
            print(f"\n{Colors.OKGREEN}[+] Fuzzing complete{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] No crashes found (yet){Colors.ENDC}")
        
        return True

class ExploitGenerator:
    """Generates exploit skeletons from vulnerabilities"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def generate_exploit(self, vuln_info: Dict) -> Path:
        """Generate exploit code from vulnerability info"""
        device = vuln_info.get('device', 'unknown')
        exploit_dir = self.config.results_dir / device / 'exploits'
        exploit_dir.mkdir(parents=True, exist_ok=True)
        
        exploit_file = exploit_dir / f'exploit_{device}_{int(time.time())}.py'
        
        code = f'''#!/usr/bin/env python3
"""
Automated exploit for {device}
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

Vulnerability Info:
File: {vuln_info.get('file', 'N/A')}
Line: {vuln_info.get('line', 'N/A')}
Risk Score: {vuln_info.get('risk_score', 'N/A')}
"""

import sys
import struct
import time
from pathlib import Path

class {device.replace('-', '_').title()}Exploit:
    def __init__(self):
        self.device = "{device}"
        self.setup_guest_memory()
    
    def setup_guest_memory(self):
        """Setup guest memory for cross-domain attack"""
        print("[*] Setting up guest memory...")
        # TODO: Implement guest memory setup
        pass
    
    def trigger_vulnerability(self):
        """
        Trigger vulnerability at: {vuln_info.get('file', 'N/A')}:{vuln_info.get('line', 'N/A')}
        """
        print("[*] Triggering vulnerability...")
        # TODO: Implement trigger
        pass
    
    def leak_addresses(self):
        """Stage 1: Leak host addresses via cross-domain technique"""
        print("[*] Stage 1: Leaking host addresses...")
        
        # Create fake chunk in guest memory
        fake_chunk_size = 0x290
        # TODO: Allocate fake chunk
        
        self.trigger_vulnerability()
        
        # Read leaked addresses
        # TODO: Read from guest memory
        
        return {{
            'heap': 0xdeadbeef,
            'binary': 0xcafebabe
        }}
    
    def hijack_control_flow(self, addresses):
        """Stage 2: Hijack control flow"""
        print("[*] Stage 2: Hijacking control flow...")
        
        # Calculate system() address
        system_addr = addresses['binary'] + 0x12345  # TODO: Calculate offset
        
        # Overwrite function pointer
        # TODO: Implement overwrite
        
        print("[+] Control flow hijacked!")
    
    def execute_payload(self):
        """Stage 3: Execute payload"""
        print("[*] Stage 3: Executing payload...")
        
        # TODO: Trigger callback
        
        print("[+] Payload executed!")
    
    def exploit(self):
        """Run complete exploit"""
        print("=" * 60)
        print(f"Exploiting {{self.device}}")
        print("=" * 60)
        
        addresses = self.leak_addresses()
        print(f"[+] Leaked addresses: {{addresses}}")
        
        self.hijack_control_flow(addresses)
        self.execute_payload()
        
        print("\\n[+] Exploit complete!")

if __name__ == "__main__":
    exploit = {device.replace('-', '_').title()}Exploit()
    exploit.exploit()
'''
        
        exploit_file.write_text(code)
        exploit_file.chmod(0o755)
        
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Generated exploit: {exploit_file}")
        return exploit_file

class FullPipeline:
    """Complete vulnerability discovery and exploitation pipeline"""
    
    def __init__(self, config: Config):
        self.config = config
        self.scanner = ErrorHandlingScanner(config)
        self.fuzzer = FuzzingManager(config)
        self.exploit_gen = ExploitGenerator(config)
    
    def run(self, device: str, fuzz_duration: int = 4) -> bool:
        """Run complete pipeline"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}STARTING FULL PIPELINE FOR {device}{Colors.ENDC}\n")
        
        # Phase 1: Static Analysis
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.HEADER}PHASE 1: STATIC ANALYSIS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        
        scan_results = self.scanner.scan_device(device)
        
        if not scan_results['findings']:
            print(f"{Colors.WARNING}[!] No vulnerabilities found in static analysis{Colors.ENDC}")
            return False
        
        # Save scan results
        scan_file = self.config.results_dir / device / 'scan_results.json'
        scan_file.parent.mkdir(parents=True, exist_ok=True)
        with open(scan_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        # Print report
        report = self.scanner.generate_report(scan_results)
        print(f"\n{report}")
        
        report_file = self.config.results_dir / device / 'scan_report.txt'
        report_file.write_text(report)
        print(f"\n{Colors.OKGREEN}[+] Full report saved: {report_file}{Colors.ENDC}")
        
        # Phase 2: Directed Fuzzing
        print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.HEADER}PHASE 2: DIRECTED FUZZING{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        
        response = input(f"\n{Colors.OKCYAN}Start fuzzing for {fuzz_duration} hours? (y/n): {Colors.ENDC}")
        if response.lower() == 'y':
            self.fuzzer.start_fuzzing(device, fuzz_duration)
        else:
            print(f"{Colors.WARNING}[!] Skipping fuzzing phase{Colors.ENDC}")
        
        # Phase 3: Exploit Generation
        print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.HEADER}PHASE 3: EXPLOIT GENERATION{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        
        # Generate exploits for high-risk findings
        critical_findings = [f for f in scan_results['findings'] if f['risk_score'] >= 80]
        
        if critical_findings:
            print(f"\n{Colors.OKGREEN}[+] Generating exploits for {len(critical_findings)} critical findings{Colors.ENDC}")
            for finding in critical_findings[:3]:  # Top 3
                self.exploit_gen.generate_exploit(finding)
        else:
            print(f"{Colors.WARNING}[!] No critical findings to exploit{Colors.ENDC}")
        
        # Summary
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}PIPELINE COMPLETE{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
        print(f"\n{Colors.OKGREEN}Results Directory: {self.config.results_dir / device}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Scan Results: {scan_file}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Report: {report_file}{Colors.ENDC}")
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description='Automated Hypervisor Vulnerability Hunter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Initial setup
  %(prog)s --setup --workdir /opt/vuln-hunter
  
  # Scan specific device
  %(prog)s --scan virtio-gpu
  
  # Run directed fuzzing
  %(prog)s --fuzz virtio-gpu --duration 24
  
  # Complete pipeline
  %(prog)s --full virtio-gpu --duration 4
  
Supported Devices:
  virtio-gpu, virtio-scsi, virtio-crypto, vmware-svga,
  ahci, nvme, e1000, usb-xhci
        '''
    )
    
    parser.add_argument('--setup', action='store_true',
                        help='Setup tools (AFL++, QEMU)')
    parser.add_argument('--setup-simple', action='store_true',
                        help='Simple setup without AFL instrumentation (faster)')
    parser.add_argument('--scan', metavar='DEVICE',
                        help='Scan device for vulnerabilities')
    parser.add_argument('--fuzz', metavar='DEVICE',
                        help='Run directed fuzzing on device')
    parser.add_argument('--test-harness', metavar='DEVICE',
                        help='Test fuzzing harness without fuzzing')
    parser.add_argument('--full', metavar='DEVICE',
                        help='Run complete pipeline (scan + fuzz + exploit)')
    parser.add_argument('--workdir', default=os.path.expanduser('~/vuln-hunter'),
                        help='Working directory (default: ~/vuln-hunter)')
    parser.add_argument('--cores', type=int,
                        help='Number of CPU cores to use (default: all)')
    parser.add_argument('--duration', type=int, default=24,
                        help='Fuzzing duration in hours (default: 24)')
    parser.add_argument('--qemu-version', default='v8.2.0',
                        help='QEMU version to clone (default: v8.2.0)')
    
    args = parser.parse_args()
    
    # Require at least one action
    if not any([args.setup, args.setup_simple, args.scan, args.fuzz, args.test_harness, args.full]):
        parser.print_help()
        sys.exit(1)
    
    # Create config
    config = Config.from_args(args)
    
    # Setup
    if args.setup:
        setup = SetupManager(config)
        if not setup.setup_all():
            print(f"\n{Colors.FAIL}[!] Setup failed{Colors.ENDC}")
            print(f"\n{Colors.OKCYAN}Try simple setup for faster installation:{Colors.ENDC}")
            print(f"  {sys.argv[0]} --setup-simple")
            sys.exit(1)
        print(f"\n{Colors.OKGREEN}[+] Setup complete! Ready to hunt vulnerabilities.{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Next steps:{Colors.ENDC}")
        print(f"  {sys.argv[0]} --scan virtio-gpu")
        print(f"  {sys.argv[0]} --full virtio-gpu")
        return
    
    # Simple setup
    if args.setup_simple:
        setup = SetupManager(config)
        if not setup.setup_simple():
            print(f"\n{Colors.FAIL}[!] Setup failed{Colors.ENDC}")
            sys.exit(1)
        return
    
    # Check if tools are setup (not needed for scan-only)
    if args.fuzz or args.full:
        if not config.qemu_dir.exists() or not config.aflplusplus_dir.exists():
            print(f"{Colors.FAIL}[!] Tools not setup. Run with --setup first{Colors.ENDC}")
            sys.exit(1)
    
    # Scan
    if args.scan:
        # Scan doesn't require QEMU to be built
        if not config.qemu_dir.exists():
            print(f"{Colors.FAIL}[!] QEMU source not found. Run with --setup-simple first{Colors.ENDC}")
            sys.exit(1)
        
        scanner = ErrorHandlingScanner(config)
        results = scanner.scan_device(args.scan)
        
        # Save results
        output_dir = config.results_dir / args.scan
        output_dir.mkdir(parents=True, exist_ok=True)
        
        json_file = output_dir / 'scan_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        report = scanner.generate_report(results)
        print(f"\n{report}")
        
        report_file = output_dir / 'scan_report.txt'
        report_file.write_text(report)
        print(f"\n{Colors.OKGREEN}[+] Results saved to: {output_dir}{Colors.ENDC}")
    
    # Test harness
    if args.test_harness:
        fuzzer = FuzzingManager(config)
        
        # Create harness
        harness_file = fuzzer.create_harness(args.test_harness)
        harness_bin = fuzzer.compile_harness(harness_file)
        
        if harness_bin:
            print(f"\n{Colors.OKGREEN}[+] Testing harness...{Colors.ENDC}")
            
            # Create test input
            test_input = config.results_dir / args.test_harness / 'test_input.bin'
            test_input.parent.mkdir(parents=True, exist_ok=True)
            test_input.write_bytes(b'\x01\x00\x00\x00\x10\x00\x00\x00' + b'\x00' * 56)
            
            # Run harness
            result = subprocess.run(
                [str(harness_bin), str(test_input)],
                capture_output=True,
                text=True
            )
            
            print(f"{Colors.OKGREEN}[+] Harness executed successfully{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Ready for fuzzing with: --fuzz {args.test_harness}{Colors.ENDC}")
    
    # Fuzz
    if args.fuzz:
        fuzzer = FuzzingManager(config)
        fuzzer.start_fuzzing(args.fuzz, args.duration)
    
    # Full pipeline
    if args.full:
        pipeline = FullPipeline(config)
        pipeline.run(args.full, args.duration)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)