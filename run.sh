
#!/bin/bash


echo "[*] clearing dmesg"
sleep 5
dmesg -c

echo "[*] Installing necessary packages."
sleep 5
apt-get install make python3-venv python3-dev ninja-build pkg-config build-essential libglib2.0-dev libpixman-1-dev libfdt-dev zlib1g-dev libsdl2-dev libslirp-dev libcap-ng-dev libattr1-dev flex bison sudo git make gcc gdb tar pip xxd binutils linux-compiler-gcc-12-x86 linux-kbuild-6.1 wget lld llvm gcc-12-plugin-dev clang zlib1g-dev -y

echo "[*] Setting up kernel parameters for AHCI exploit..."
sleep 5
# Check current cmdline
if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    
    # Check if we need to modify GRUB
    if ! grep -qw "nokaslr" /etc/default/grub; then
        echo "[*] Adding exploit-friendly kernel parameters..."
        
        # Read current GRUB_CMDLINE_LINUX line
        if grep -q '^GRUB_CMDLINE_LINUX="' /etc/default/grub; then
            # Add parameters for better exploitation
            sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="nokaslr pci=realloc=off pci=nobar /' /etc/default/grub
            echo "[+] Added: nokaslr pci=realloc=off pci=nobar"
        elif grep -q '^GRUB_CMDLINE_LINUX_DEFAULT="' /etc/default/grub; then
            sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="nokaslr pci=realloc=off pci=nobar /' /etc/default/grub
            echo "[+] Added: nokaslr pci=realloc=off pci=nobar"
        else
            echo "[!] Could not find GRUB_CMDLINE_LINUX in /etc/default/grub"
            exit 1
        fi
        
        update-grub
        echo "[+] Kernel parameters added. You must reboot for changes to take effect."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            reboot
        else
            echo "[!] Kernel parameters will be active after reboot."
        fi
    else
        echo "[*] 'nokaslr' already in GRUB. Just reboot to disable KASLR."
    fi
fi

# Additional checks for AHCI exploitation
echo "[*] Checking AHCI-related settings..."

# Check if AHCI driver is loaded
if lsmod | grep -q ahci; then
    echo "[+] AHCI driver is loaded"
else
    echo "[!] AHCI driver not loaded. Attempting to load..."
    modprobe ahci 2>/dev/null && echo "[+] AHCI driver loaded" || echo "[!] Failed to load AHCI"
fi

# Check if we can access /dev/mem
if [ -w /dev/mem ]; then
    echo "[+] /dev/mem is writable"
else
    echo "[!] /dev/mem is not writable. Root access required."
fi

# Check for required tools
echo "[*] Checking for required tools..."
for tool in python3 objdump readelf nm; do
    if command -v $tool >/dev/null 2>&1; then
        echo "[+] $tool found"
    else
        echo "[!] $tool not found"
    fi
done
echo "[*] Setup complete. You can now run the AHCI exploit."

echo "[*] Installing necessary headers."
sleep 5
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
dpkg -i *.deb || true


echo "[*] Disabling randomize_va_space."
sleep 5
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

echo "[*] Setting up prober."
sleep 5
cd /root/kvm_probin/prober
make
make install
cp kvm_prober /bin
kvm_prober
sleep 5

echo "[*] Setting up workspace."
sleep 5
cd /root/kvm_probin/hunter
sleep 5
python3 vuln_hunter.py --setup --workdir /opt/vuln-hunter

cd /opt/vuln-hunter/qemu/build
make install
cd /opt/vuln-hunter/A*
make install
cd /root/kvm_probin/hunter

echo "[*] Discovering vulnerabilities in kvm/qemu error handling."
sleep 5
python3 hunter.py
