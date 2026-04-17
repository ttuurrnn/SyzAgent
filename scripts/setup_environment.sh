#!/bin/bash
#
# SyzDirect Experiment Environment Setup Script
#
# This script sets up the complete environment for SyzDirect experiments:
# - Host dependencies
# - Kernel source and build
# - VM image creation
# - syzkaller configuration
#

set -e

# Configuration
WORK_DIR="/work"
KERNEL_VERSION="${KERNEL_VERSION:-6.1}"
KERNEL_COMMIT="${KERNEL_COMMIT:-}"
IMAGE_SIZE="${IMAGE_SIZE:-2G}"
NUM_CPUS="${NUM_CPUS:-2}"
MEM_SIZE="${MEM_SIZE:-2048}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

#
# Phase 1: Install Host Dependencies
#
install_dependencies() {
    log_info "Installing host dependencies..."
    
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        git build-essential libssl-dev libelf-dev flex bison bc \
        qemu-system-x86 qemu-utils \
        debootstrap \
        gcc-multilib g++-multilib \
        python3 python3-pip python3-venv \
        wget curl jq \
        libncurses-dev \
        dwarves \
        zstd
        
    # Check for Go
    if ! command -v go &> /dev/null; then
        log_info "Installing Go..."
        wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    fi
    
    # Check for Clang
    if ! command -v clang &> /dev/null; then
        log_info "Installing Clang..."
        sudo apt-get install -y -qq clang-17 llvm-17 lld-17
        sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100
        sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100
    fi
    
    log_info "Dependencies installed successfully"
}

#
# Phase 2: Setup Kernel Source
#
setup_kernel() {
    log_info "Setting up kernel source..."
    
    cd "$WORK_DIR"
    
    if [ ! -d "linux-src" ] || [ ! -f "linux-src/Makefile" ]; then
        log_info "Cloning kernel source (this may take a while)..."
        
        # Use shallow clone for faster download
        if [ -n "$KERNEL_COMMIT" ]; then
            git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-src
            cd linux-src
            git fetch --depth=1 origin "$KERNEL_COMMIT"
            git checkout "$KERNEL_COMMIT"
        else
            git clone --depth=1 --branch "v${KERNEL_VERSION}" \
                https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-src
        fi
    else
        log_info "Kernel source already exists"
    fi
    
    log_info "Kernel source ready"
}

#
# Phase 3: Configure and Build Kernel
#
build_kernel() {
    log_info "Building kernel with fuzzing configuration..."
    
    cd "$WORK_DIR/linux-src"
    
    # Create fuzzing-optimized config
    make defconfig
    
    # Enable required options for syzkaller
    ./scripts/config --enable CONFIG_KCOV
    ./scripts/config --enable CONFIG_KCOV_INSTRUMENT_ALL
    ./scripts/config --enable CONFIG_KCOV_ENABLE_COMPARISONS
    ./scripts/config --enable CONFIG_DEBUG_FS
    ./scripts/config --enable CONFIG_DEBUG_INFO
    ./scripts/config --enable CONFIG_DEBUG_INFO_DWARF4
    ./scripts/config --enable CONFIG_KALLSYMS
    ./scripts/config --enable CONFIG_KALLSYMS_ALL
    ./scripts/config --enable CONFIG_NAMESPACES
    ./scripts/config --enable CONFIG_USER_NS
    ./scripts/config --enable CONFIG_UTS_NS
    ./scripts/config --enable CONFIG_IPC_NS
    ./scripts/config --enable CONFIG_PID_NS
    ./scripts/config --enable CONFIG_NET_NS
    ./scripts/config --enable CONFIG_CGROUP_PIDS
    ./scripts/config --enable CONFIG_MEMCG
    ./scripts/config --enable CONFIG_CONFIGFS_FS
    ./scripts/config --enable CONFIG_SECURITYFS
    ./scripts/config --enable CONFIG_KASAN
    ./scripts/config --enable CONFIG_KASAN_INLINE
    ./scripts/config --enable CONFIG_FAULT_INJECTION
    ./scripts/config --enable CONFIG_FAULT_INJECTION_DEBUG_FS
    ./scripts/config --enable CONFIG_FAILSLAB
    ./scripts/config --enable CONFIG_FAIL_PAGE_ALLOC
    ./scripts/config --enable CONFIG_FAIL_MAKE_REQUEST
    ./scripts/config --enable CONFIG_FAIL_IO_TIMEOUT
    ./scripts/config --enable CONFIG_FAIL_FUTEX
    ./scripts/config --enable CONFIG_LOCKDEP
    ./scripts/config --enable CONFIG_PROVE_LOCKING
    ./scripts/config --enable CONFIG_DEBUG_ATOMIC_SLEEP
    ./scripts/config --enable CONFIG_PROVE_RCU
    ./scripts/config --enable CONFIG_DEBUG_VM
    ./scripts/config --enable CONFIG_REFCOUNT_FULL
    ./scripts/config --enable CONFIG_FORTIFY_SOURCE
    ./scripts/config --enable CONFIG_HARDENED_USERCOPY
    ./scripts/config --enable CONFIG_LOCKUP_DETECTOR
    ./scripts/config --enable CONFIG_SOFTLOCKUP_DETECTOR
    ./scripts/config --enable CONFIG_HARDLOCKUP_DETECTOR
    ./scripts/config --enable CONFIG_DETECT_HUNG_TASK
    ./scripts/config --enable CONFIG_WQ_WATCHDOG
    ./scripts/config --disable CONFIG_RANDOMIZE_BASE
    
    # Enable common subsystems for fuzzing
    ./scripts/config --enable CONFIG_NET
    ./scripts/config --enable CONFIG_INET
    ./scripts/config --enable CONFIG_IPV6
    ./scripts/config --enable CONFIG_NETFILTER
    ./scripts/config --enable CONFIG_BLK_DEV_LOOP
    ./scripts/config --enable CONFIG_BLK_DEV_RAM
    
    # Filesystems
    ./scripts/config --module CONFIG_EXT4_FS
    ./scripts/config --module CONFIG_BTRFS_FS
    ./scripts/config --module CONFIG_F2FS_FS
    ./scripts/config --module CONFIG_XFS_FS
    
    make olddefconfig
    
    # Build kernel
    log_info "Compiling kernel (this will take a while)..."
    make -j$(nproc) 2>&1 | tail -20
    
    # Copy vmlinux to build directory
    mkdir -p "$WORK_DIR/linux-build"
    cp vmlinux "$WORK_DIR/linux-build/"
    cp .config "$WORK_DIR/linux-build/"
    cp arch/x86/boot/bzImage "$WORK_DIR/linux-build/"
    
    log_info "Kernel build complete"
}

#
# Phase 4: Create VM Image
#
create_vm_image() {
    log_info "Creating VM image..."
    
    cd "$WORK_DIR/images"
    
    if [ -f "bullseye.img" ]; then
        log_info "VM image already exists"
        return
    fi
    
    # Create image using syzkaller's script
    if [ -f "$WORK_DIR/syzkaller/tools/create-image.sh" ]; then
        log_info "Using syzkaller's create-image.sh..."
        
        # Create image
        "$WORK_DIR/syzkaller/tools/create-image.sh" \
            --distribution bullseye \
            --feature minimal \
            --seek "$IMAGE_SIZE"
            
    else
        log_info "Creating image manually with debootstrap..."
        
        # Create raw image
        qemu-img create -f raw bullseye.img "$IMAGE_SIZE"
        
        # Format and mount
        mkfs.ext4 bullseye.img
        mkdir -p /tmp/mnt
        sudo mount -o loop bullseye.img /tmp/mnt
        
        # Debootstrap
        sudo debootstrap --include=openssh-server,curl,wget,gcc,make bullseye /tmp/mnt
        
        # Configure SSH
        sudo mkdir -p /tmp/mnt/root/.ssh
        
        # Generate SSH key if not exists
        if [ ! -f "$WORK_DIR/images/bullseye.id_rsa" ]; then
            ssh-keygen -t rsa -b 4096 -f "$WORK_DIR/images/bullseye.id_rsa" -N ""
        fi
        
        sudo cp "$WORK_DIR/images/bullseye.id_rsa.pub" /tmp/mnt/root/.ssh/authorized_keys
        sudo chmod 600 /tmp/mnt/root/.ssh/authorized_keys
        
        # Configure network
        echo "auto eth0" | sudo tee /tmp/mnt/etc/network/interfaces.d/eth0
        echo "iface eth0 inet dhcp" | sudo tee -a /tmp/mnt/etc/network/interfaces.d/eth0
        
        # Set root password (for debugging)
        echo "root:root" | sudo chpasswd -R /tmp/mnt
        
        # Enable serial console
        sudo ln -s /lib/systemd/system/getty@.service \
            /tmp/mnt/etc/systemd/system/getty.target.wants/getty@ttyS0.service
            
        sudo umount /tmp/mnt
    fi
    
    # Convert to qcow2 for snapshots
    if [ ! -f "bullseye.qcow2" ]; then
        qemu-img convert -f raw -O qcow2 bullseye.img bullseye.qcow2
    fi
    
    log_info "VM image created"
}

#
# Phase 5: Generate SSH Keys
#
setup_ssh_keys() {
    log_info "Setting up SSH keys..."
    
    cd "$WORK_DIR/images"
    
    if [ ! -f "bullseye.id_rsa" ]; then
        ssh-keygen -t rsa -b 4096 -f bullseye.id_rsa -N ""
        log_info "SSH keys generated"
    else
        log_info "SSH keys already exist"
    fi
}

#
# Phase 6: Build syzkaller
#
build_syzkaller() {
    log_info "Building syzkaller..."
    
    cd "$WORK_DIR/syzkaller"
    
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    if [ ! -f "bin/syz-manager" ]; then
        make -j$(nproc)
    else
        log_info "syzkaller already built"
    fi
    
    log_info "syzkaller build complete"
}

#
# Phase 7: Create syzkaller config
#
create_syzkaller_config() {
    log_info "Creating syzkaller configuration..."
    
    cat > "$WORK_DIR/configs/syzkaller.cfg" << EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "$WORK_DIR/runs/baseline-syzkaller/workdir",
    "kernel_obj": "$WORK_DIR/linux-build",
    "image": "$WORK_DIR/images/bullseye.qcow2",
    "sshkey": "$WORK_DIR/images/bullseye.id_rsa",
    "syzkaller": "$WORK_DIR/syzkaller",
    "procs": 2,
    "type": "qemu",
    "vm": {
        "count": 1,
        "kernel": "$WORK_DIR/linux-build/bzImage",
        "cpu": $NUM_CPUS,
        "mem": $MEM_SIZE
    }
}
EOF
    
    log_info "Configuration created at $WORK_DIR/configs/syzkaller.cfg"
}

#
# Phase 8: Create SyzDirect config
#
create_syzdirect_config() {
    log_info "Creating SyzDirect configuration..."
    
    cat > "$WORK_DIR/configs/syzdirect.cfg" << EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56742",
    "workdir": "$WORK_DIR/runs/baseline-syzdirect/workdir",
    "kernel_obj": "$WORK_DIR/linux-build",
    "kernel_src": "$WORK_DIR/linux-src",
    "image": "$WORK_DIR/images/bullseye.qcow2",
    "sshkey": "$WORK_DIR/images/bullseye.id_rsa",
    "syzkaller": "$WORK_DIR/syzkaller",
    "procs": 2,
    "type": "qemu",
    "vm": {
        "count": 1,
        "kernel": "$WORK_DIR/linux-build/bzImage",
        "cpu": $NUM_CPUS,
        "mem": $MEM_SIZE
    },
    "syzdirect": {
        "enabled": true,
        "template_dir": "$WORK_DIR/SyzDirect/templates",
        "distance_map": "$WORK_DIR/SyzDirect/distances.json",
        "log_dir": "$WORK_DIR/SyzDirect/logs"
    }
}
EOF
    
    log_info "SyzDirect configuration created"
}

#
# Phase 9: Setup Python environment for agents
#
setup_python_env() {
    log_info "Setting up Python environment..."
    
    cd "$WORK_DIR/SyzDirect"
    
    python3 -m venv venv
    source venv/bin/activate
    
    pip install --upgrade pip
    pip install dataclasses-json pyyaml requests
    
    log_info "Python environment ready"
}

#
# Main
#
main() {
    log_info "Starting SyzDirect experiment environment setup..."
    log_info "Work directory: $WORK_DIR"
    
    # Create directories
    mkdir -p "$WORK_DIR"/{syzkaller,SyzDirect,linux-src,linux-build,images,targets,runs/{baseline-syzkaller,baseline-syzdirect,agent-loop}/workdir,configs,logs}
    
    # Run setup phases
    install_dependencies
    
    # Check if we should skip heavy operations
    if [ "${SKIP_KERNEL:-0}" != "1" ]; then
        setup_kernel
        build_kernel
    else
        log_warn "Skipping kernel setup (SKIP_KERNEL=1)"
    fi
    
    if [ "${SKIP_IMAGE:-0}" != "1" ]; then
        setup_ssh_keys
        create_vm_image
    else
        log_warn "Skipping VM image creation (SKIP_IMAGE=1)"
    fi
    
    build_syzkaller
    create_syzkaller_config
    create_syzdirect_config
    setup_python_env
    
    log_info "============================================"
    log_info "Setup complete!"
    log_info "============================================"
    log_info ""
    log_info "Next steps:"
    log_info "  1. Define targets in $WORK_DIR/targets/"
    log_info "  2. Run static analysis: python3 $WORK_DIR/SyzDirect/source/analyzer/syscall_analyzer.py"
    log_info "  3. Start fuzzing: $WORK_DIR/SyzDirect/scripts/run_experiment.sh"
    log_info ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-kernel)
            export SKIP_KERNEL=1
            shift
            ;;
        --skip-image)
            export SKIP_IMAGE=1
            shift
            ;;
        --kernel-version)
            KERNEL_VERSION="$2"
            shift 2
            ;;
        --kernel-commit)
            KERNEL_COMMIT="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

main
