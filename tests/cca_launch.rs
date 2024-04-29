//#[cfg(all(feature = "snp", target_os = "linux"))]
use std::slice::from_raw_parts_mut;

//#[cfg(all(feature = "snp", target_os = "linux"))]
//use sev::firmware::host::Firmware;

//#[cfg(all(feature = "snp", target_os = "linux"))]
//use sev::launch::snp::*;

//#[cfg(all(feature = "snp", target_os = "linux"))]
use kvm_bindings::kvm_cap_arm_rme_config_item;
use kvm_bindings::kvm_cap_arm_rme_populate_realm_args;
use kvm_bindings::kvm_create_guest_memfd;
use kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3;
use kvm_bindings::kvm_enable_cap;
use kvm_bindings::kvm_userspace_memory_region2;
use kvm_bindings::kvm_vcpu_init;
use kvm_bindings::KVM_ARM_RME_POPULATE_FLAGS_MEASURE;
use kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
use kvm_bindings::KVM_CAP_ARM_RME;
use kvm_bindings::KVM_CAP_ARM_RME_ACTIVATE_REALM;
use kvm_bindings::KVM_CAP_ARM_RME_CFG_HASH_ALGO;
use kvm_bindings::KVM_CAP_ARM_RME_CONFIG_REALM;
use kvm_bindings::KVM_CAP_ARM_RME_CREATE_RD;
use kvm_bindings::KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256;
use kvm_bindings::KVM_CAP_ARM_RME_POPULATE_REALM;
use kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT;
use kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR;
use kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL;
use kvm_bindings::KVM_MEM_GUEST_MEMFD;
use kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST;
use kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST;
use kvm_ioctls::Cap;

//#[cfg(all(feature = "snp", target_os = "linux"))]
use kvm_ioctls::{Kvm, VcpuExit};

use std::cmp;
use std::ptr;

use kvm_bindings::KVM_ARM_VCPU_REC;
use kvm_bindings::KVM_VM_TYPE_ARM_IPA_SIZE_MASK;
use kvm_bindings::KVM_VM_TYPE_ARM_REALM;
use std::os::fd::RawFd;

//#[cfg(all(feature = "snp", target_os = "linux"))]
//#[cfg_attr(not(has_sev), ignore)]
#[test]
fn cca() {
    let kvm_fd = Kvm::new().unwrap();

    let code: &mut [u8; 4096] = &mut [0x0; 4096];
    let hvc: &[u8; 8] = &[0x01, 0x00, 0x00, 0xf9, 0x00, 0x00, 0x00, 0x14];
    code[..hvc.len()].copy_from_slice(&hvc[..]);

    if !(kvm_fd.check_extension(Cap::ArmRme)) {
        println!("RME not supported!");
        return;
    }

    const MEM_ADDR: u64 = 0x10000;

    let max_ipa = MEM_ADDR + code.len() as u64 - 1;
    let mut ipa_bits = cmp::max(32, 1 << max_ipa.trailing_zeros());

    // realm needs double the IPA space
    ipa_bits += 1;

    let vm_fd = kvm_fd
        .create_vm_with_type(
            (KVM_VM_TYPE_ARM_REALM | (ipa_bits & KVM_VM_TYPE_ARM_IPA_SIZE_MASK)).into(),
        )
        .unwrap();

    // create IRQ chip in kernel: IRQCHIP_GICV3
    let mut gic_device = kvm_bindings::kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        fd: 0,
        /* flags: KVM_CREATE_DEVICE_TEST, set this flag to try if type is working */
        flags: 0,
    };

    let gic_fd = vm_fd.create_device(&mut gic_device).unwrap();

    // these values are hard-coded based on kvmtool
    let gic_redists_base: u64 = 0x3FFD0000;
    let dist_addr: u64 = 0x3FFF0000;
    let redist_attr = kvm_bindings::kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST),
        addr: ptr::addr_of!(gic_redists_base) as u64,
    };

    gic_fd.set_device_attr(&redist_attr).unwrap();

    let dist_attr = kvm_bindings::kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST),
        addr: ptr::addr_of!(dist_addr) as u64,
    };

    gic_fd.set_device_attr(&dist_attr).unwrap();

    // allocate a 1kB page of memory for the address space of the VM.
    let address_space = unsafe { libc::mmap(0 as _, code.len(), 3, 34, -1, 0) };

    if address_space == libc::MAP_FAILED {
        panic!("mmap() failed");
    }

    let address_space: &mut [u8] =
        unsafe { from_raw_parts_mut(address_space as *mut u8, code.len()) };

    address_space[..code.len()].copy_from_slice(&code[..]);

    let userspace_addr = address_space as *const [u8] as *const u8 as u64;

    let gmem = kvm_create_guest_memfd {
        size: code.len() as _,
        flags: 0,
        reserved: [0; 6],
    };

    let id: RawFd = vm_fd.create_guest_memfd(gmem).unwrap();

    let mem_region = kvm_userspace_memory_region2 {
        slot: 0,
        flags: KVM_MEM_GUEST_MEMFD,
        guest_phys_addr: MEM_ADDR,
        memory_size: code.len() as _,
        userspace_addr,
        guest_memfd_offset: 0,
        guest_memfd: id as u32,
        pad1: 0,
        pad2: [0; 14],
    };

    unsafe {
        vm_fd.set_user_memory_region2(mem_region).unwrap();
    }

    let mut vcpu_fd = vm_fd.create_vcpu(0).unwrap();

    let mut kvi = kvm_vcpu_init::default();
    vm_fd.get_preferred_target(&mut kvi).unwrap();

    kvi.features[0] |= 1u32 << KVM_ARM_VCPU_PSCI_0_2;

    // this fails
    // kvi.features[0] |= 1u32 << KVM_ARM_VCPU_SVE;

    vcpu_fd.vcpu_init(&kvi).unwrap();

    // initialize vGiC after VCPU creation. Note that this is a minimal setup
    let vgic_init_attr = kvm_bindings::kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0x0,
    };

    gic_fd.set_device_attr(&vgic_init_attr).unwrap();

    // set measurement algo
    let mut hash_algo_cfg: kvm_cap_arm_rme_config_item = Default::default();
    hash_algo_cfg.cfg = KVM_CAP_ARM_RME_CFG_HASH_ALGO;
    hash_algo_cfg.data.hash_algo = KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256;

    let mut rme_config: kvm_enable_cap = Default::default();

    rme_config.cap = KVM_CAP_ARM_RME;
    rme_config.args[0] = KVM_CAP_ARM_RME_CONFIG_REALM;
    rme_config.args[1] = ptr::addr_of!(hash_algo_cfg) as u64;

    vm_fd.enable_cap(&rme_config).unwrap();

    // TODO: add realm personalisation value

    // create realm descriptor
    rme_config.cap = KVM_CAP_ARM_RME;
    rme_config.args[0] = KVM_CAP_ARM_RME_CREATE_RD;
    vm_fd.enable_cap(&rme_config).unwrap();

    // populate Realm RAM
    // these are mapping pages
    let mut populate_args: kvm_cap_arm_rme_populate_realm_args = Default::default();

    // ALIGN_DOWN(start, SZ_4K);
    // size must also be aligned
    populate_args.populate_ipa_base = MEM_ADDR;
    populate_args.populate_ipa_size = code.len() as u64;
    populate_args.flags = KVM_ARM_RME_POPULATE_FLAGS_MEASURE;

    rme_config.cap = KVM_CAP_ARM_RME;
    rme_config.args[0] = KVM_CAP_ARM_RME_POPULATE_REALM;
    rme_config.args[1] = ptr::addr_of!(populate_args) as u64;
    vm_fd.enable_cap(&rme_config).unwrap();

    let core_reg_base: u64 = 0x6030_0000_0010_0000;

    // set x1 to known value
    let nr_magic: u64 = 0x1987;
    vcpu_fd
        .set_one_reg(core_reg_base + 2 * 1, &(nr_magic as u128).to_le_bytes())
        .unwrap();

    // set x0 to trigger a mmio exit accessing to something less than 1 << ipa_bits - 1 won't
    // trigger a mmio exit
    let mmio_addr: u64 = (1 << ipa_bits - 1) + 0x1000;
    vcpu_fd
        .set_one_reg(core_reg_base + 2 * 0, &(mmio_addr as u128).to_le_bytes())
        .unwrap();

    let guest_addr: u64 = MEM_ADDR;
    vcpu_fd
        .set_one_reg(core_reg_base + 2 * 32, &(guest_addr as u128).to_le_bytes())
        .unwrap();

    let feature = KVM_ARM_VCPU_REC as i32;
    vcpu_fd.vcpu_finalize(&feature).unwrap();

    // activate realm
    rme_config.cap = KVM_CAP_ARM_RME;
    rme_config.args[0] = KVM_CAP_ARM_RME_ACTIVATE_REALM;
    vm_fd.enable_cap(&rme_config).unwrap();

    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::MmioWrite(addr, data) => {
                println!("Write access to {} of {:?}", addr, data);
                break;
            }
            exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
        }
    }
}
