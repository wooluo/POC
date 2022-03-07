#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1757.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126897);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2018-16871", "CVE-2018-20836", "CVE-2019-10126", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11599", "CVE-2019-12614", "CVE-2019-12817", "CVE-2019-13233");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1757)");
  script_summary(english:"Check for the openSUSE-2019-1757 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2019-10638: A device could be tracked by an attacker
    using the IP ID values the kernel produces for
    connection-less protocols (e.g., UDP and ICMP). When
    such traffic is sent to multiple destination IP
    addresses, it is possible to obtain hash collisions (of
    indices to the counter array) and thereby obtain the
    hashing key (via enumeration). An attack may be
    conducted by hosting a crafted web page that uses WebRTC
    or gQUIC to force UDP traffic to attacker-controlled IP
    addresses (bnc#1140575).

  - CVE-2019-10639: The Linux kernel allowed Information
    Exposure (partial kernel address disclosure), leading to
    a KASLR bypass. Specifically, it is possible to extract
    the KASLR kernel image offset using the IP ID values the
    kernel produces for connection-less protocols (e.g., UDP
    and ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and thereby
    obtain the hashing key (via enumeration). This key
    contains enough bits from a kernel address (of a static
    variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is exposed.
    This attack can be carried out remotely, by the attacker
    forcing the target device to send UDP or ICMP (or
    certain other) traffic to attacker-controlled IP
    addresses. Forcing a server to send UDP traffic is
    trivial if the server is a DNS server. ICMP traffic is
    trivial if the server answers ICMP Echo requests (ping).
    For client targets, if the target visits the attacker's
    web page, then WebRTC or gQUIC can be used to force UDP
    traffic to attacker-controlled IP addresses. NOTE: this
    attack against KASLR became viable in 4.1 because IP ID
    generation was changed to have a dependency on an
    address associated with a network namespace
    (bnc#1140577).

  - CVE-2019-13233: In arch/x86/lib/insn-eval.c there was a
    use-after-free for access to an LDT entry because of a
    race condition between modify_ldt() and a #BR exception
    for an MPX bounds violation (bnc#1140454).

  - CVE-2018-20836: There was a race condition in
    smp_task_timedout() and smp_task_done() in
    drivers/scsi/libsas/sas_expander.c, leading to a
    use-after-free (bnc#1134395).

  - CVE-2019-10126: A heap based buffer overflow in
    mwifiex_uap_parse_tail_ies function in
    drivers/net/wireless/marvell/mwifiex/ie.c might have
    lead to memory corruption and possibly other
    consequences (bnc#1136935).

  - CVE-2019-11599: The coredump implementation in the Linux
    kernel did not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs,
    which allowed local users to obtain sensitive
    information, cause a denial of service, or possibly have
    unspecified other impact by triggering a race condition
    with mmget_not_zero or get_task_mm calls. This is
    related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and
    drivers/infiniband/core/uverbs_main.c (bnc#1133738).

  - CVE-2019-12817: arch/powerpc/mm/mmu_context_book3s64.c
    in the Linux kernel for powerpc has a bug where
    unrelated processes may be able to read/write to one
    another's virtual memory under certain conditions via an
    mmap above 512 TB. Only a subset of powerpc systems are
    affected (bnc#1138263).

  - CVE-2019-12614: An issue was discovered in
    dlpar_parse_cc_property in
    arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel. There was an unchecked kstrdup of prop->name,
    which might allow an attacker to cause a denial of
    service (NULL pointer dereference and system crash)
    (bnc#1137194).

  - CVE-2018-16871: A NULL pointer dereference due to an
    anomalized NFS message sequence was fixed.
    (bnc#1137103).

The following non-security bugs were fixed :

  - 6lowpan: Off by one handling ->nexthdr (bsc#1051510).

  - Abort file_remove_privs() for non-reg. files
    (bsc#1140888).

  - ACPICA: Clear status of GPEs on first direct enable
    (bsc#1111666).

  - ACPI: PM: Allow transitions to D0 to occur in special
    cases (bsc#1051510).

  - ACPI: PM: Avoid evaluating _PS3 on transitions from
    D3hot to D3cold (bsc#1051510).

  - af_key: unconditionally clone on broadcast
    (bsc#1051510).

  - alsa: firewire-lib/fireworks: fix miss detection of
    received MIDI messages (bsc#1051510).

  - alsa: hda - Force polling mode on CNL for fixing codec
    communication (bsc#1051510).

  - alsa: hda/realtek: Add quirks for several Clevo notebook
    barebones (bsc#1051510).

  - alsa: hda/realtek - Change front mic location for Lenovo
    M710q (bsc#1051510).

  - alsa: line6: Fix write on zero-sized buffer
    (bsc#1051510).

  - alsa: seq: fix incorrect order of dest_client/dest_ports
    arguments (bsc#1051510).

  - alsa: usb-audio: Fix parse of UAC2 Extension Units
    (bsc#1111666).

  - alsa: usb-audio: fix sign unintended sign extension on
    left shifts (bsc#1051510).

  - apparmor: enforce nullbyte at end of tag string
    (bsc#1051510).

  - ASoC: cx2072x: fix integer overflow on unsigned int
    multiply (bsc#1111666).

  - audit: fix a memory leak bug (bsc#1051510).

  - ax25: fix inconsistent lock state in ax25_destroy_timer
    (bsc#1051510).

  - blk-mq: free hw queue's resource in hctx's release
    handler (bsc#1140637).

  - block: Fix a NULL pointer dereference in
    generic_make_request() (bsc#1139771).

  - bluetooth: Fix faulty expression for minimum encryption
    key size check (bsc#1140328).

  - bpf, devmap: Add missing bulk queue free (bsc#1109837).

  - bpf, devmap: Add missing RCU read lock on flush
    (bsc#1109837).

  - bpf, devmap: Fix premature entry free on destroying map
    (bsc#1109837).

  - bpf: devmap: fix use-after-free Read in
    __dev_map_entry_free (bsc#1109837).

  - bpf: lpm_trie: check left child of last leftmost node
    for NULL (bsc#1109837).

  - bpf: sockmap fix msg->sg.size account on ingress skb
    (bsc#1109837).

  - bpf: sockmap, fix use after free from sleep in psock
    backlog workqueue (bsc#1109837).

  - bpf: sockmap remove duplicate queue free (bsc#1109837).

  - bpf, tcp: correctly handle DONT_WAIT flags and timeo ==
    0 (bsc#1109837).

  - can: af_can: Fix error path of can_init() (bsc#1051510).

  - can: flexcan: fix timeout when set small bitrate
    (bsc#1051510).

  - can: purge socket error queue on sock destruct
    (bsc#1051510).

  - ceph: factor out ceph_lookup_inode() (bsc#1138681).

  - ceph: fix NULL pointer deref when debugging is enabled
    (bsc#1138681).

  - ceph: fix potential use-after-free in
    ceph_mdsc_build_path (bsc#1138681).

  - ceph: flush dirty inodes before proceeding with remount
    (bsc#1138681).

  - ceph: flush dirty inodes before proceeding with remount
    (bsc#1140405).

  - ceph: print inode number in __caps_issued_mask debugging
    messages (bsc#1138681).

  - ceph: quota: fix quota subdir mounts (bsc#1138681).

  - ceph: remove duplicated filelock ref increase
    (bsc#1138681).

  - cfg80211: fix memory leak of wiphy device name
    (bsc#1051510).

  - clk: rockchip: Turn on 'aclk_dmac1' for suspend on
    rk3288 (bsc#1051510).

  - clk: tegra: Fix PLLM programming on Tegra124+ when PMC
    overrides divider (bsc#1051510).

  - coresight: etb10: Fix handling of perf mode
    (bsc#1051510).

  - coresight: etm4x: Add support to enable ETMv4.2
    (bsc#1051510).

  - cpu/topology: Export die_id (jsc#SLE-5454).

  - crypto: algapi - guard against uninitialized spawn list
    in crypto_remove_spawns (bsc#1133401).

  - crypto: cryptd - Fix skcipher instance memory leak
    (bsc#1051510).

  - crypto: user - prevent operating on larval algorithms
    (bsc#1133401).

  - dax: Fix xarray entry association for mixed mappings
    (bsc#1140893).

  - device core: Consolidate locking and unlocking of parent
    and device (bsc#1106383).

  - dmaengine: imx-sdma: remove BD_INTR for channel0
    (bsc#1051510).

  - doc: Cope with the deprecation of AutoReporter
    (bsc#1051510).

  - Documentation/ABI: Document umwait control sysfs
    interfaces (jsc#SLE-5187).

  - Documentation: DMA-API: fix a function name of
    max_mapping_size (bsc#1140954).

  - Do not restrict NFSv4.2 on openSUSE (bsc#1138719).

  - driver core: Establish order of operations for
    device_add and device_del via bitflag (bsc#1106383).

  - driver core: Probe devices asynchronously instead of the
    driver (bsc#1106383).

  - drivers/base/devres: introduce devm_release_action()
    (bsc#1103992).

  - drivers/base/devres: introduce devm_release_action()
    (bsc#1103992 FATE#326009).

  - drivers/base: Introduce kill_device() (bsc#1139865).

  - drivers/base: kABI fixes for struct device_private
    (bsc#1106383).

  - drivers: depend on HAS_IOMEM for
    devm_platform_ioremap_resource() (bsc#1136333
    jsc#SLE-4994).

  - drivers: fix a typo in the kernel doc for
    devm_platform_ioremap_resource() (bsc#1136333
    jsc#SLE-4994).

  - Drivers: misc: fix out-of-bounds access in function
    param_set_kgdbts_var (bsc#1051510).

  - drivers: provide devm_platform_ioremap_resource()
    (bsc#1136333 jsc#SLE-4994).

  - drivers/rapidio/devices/rio_mport_cdev.c: fix resource
    leak in error handling path in 'rio_dma_transfer()'
    (bsc#1051510).

  - drivers/rapidio/rio_cm.c: fix potential oops in
    riocm_ch_listen() (bsc#1051510).

  - drivers: thermal: tsens: Do not print error message on
    -EPROBE_DEFER (bsc#1051510).

  - drm/amdgpu/gfx9: use reset default for PA_SC_FIFO_SIZE
    (bsc#1051510).

  - drm/amd/powerplay: use hardware fan control if no
    powerplay fan table (bsc#1111666).

  - drm/arm/hdlcd: Actually validate CRTC modes
    (bsc#1111666).

  - drm/arm/hdlcd: Allow a bit of clock tolerance
    (bsc#1051510).

  - drm/arm/mali-dp: Add a loop around the second set CVAL
    and try 5 times (bsc#1111666).

  - drm/etnaviv: add missing failure path to destroy
    suballoc (bsc#1111666).

  - drm/fb-helper: generic: Do not take module ref for fbcon
    (bsc#1111666).

  - drm: Fix drm_release() and device unplug (bsc#1111666).

  - drm/i915: Add new AML_ULX support list (jsc#SLE-4986).

  - drm/i915: Add new ICL PCI ID (jsc#SLE-4986).

  - drm/i915/aml: Add new Amber Lake PCI ID (jsc#SLE-4986).

  - drm/i915: Apply correct ddi translation table for AML
    device (jsc#SLE-4986).

  - drm/i915: Attach the pci match data to the device upon
    creation (jsc#SLE-4986).

  - drm/i915/cfl: Adding another PCI Device ID
    (jsc#SLE-4986).

  - drm/i915/cml: Add CML PCI IDS (jsc#SLE-4986).

  - drm/i915/dmc: protect against reading random memory
    (bsc#1051510).

  - drm/i915: Fix uninitialized mask in
    intel_device_info_subplatform_init (jsc#SLE-4986).

  - drm/i915/gvt: ignore unexpected pvinfo write
    (bsc#1051510).

  - drm/i915/icl: Adding few more device IDs for Ice Lake
    (jsc#SLE-4986).

  - drm/i915: Introduce concept of a sub-platform
    (jsc#SLE-4986).

  - drm/i915: Mark AML 0x87CA as ULX (jsc#SLE-4986).

  - drm/i915: Move final cleanup of drm_i915_private to
    i915_driver_destroy (jsc#SLE-4986).

  - drm/i915: Remove redundant device id from IS_IRONLAKE_M
    macro (jsc#SLE-4986).

  - drm/i915: Split Pineview device info into desktop and
    mobile (jsc#SLE-4986).

  - drm/i915: Split some PCI ids into separate groups
    (jsc#SLE-4986).

  - drm/i915: start moving runtime device info to a separate
    struct (jsc#SLE-4986).

  - drm/imx: notify drm core before sending event during
    crtc disable (bsc#1111666).

  - drm/imx: only send event on crtc disable if kept
    disabled (bsc#1111666).

  - drm: panel-orientation-quirks: Add quirk for GPD MicroPC
    (bsc#1111666).

  - drm: panel-orientation-quirks: Add quirk for GPD pocket2
    (bsc#1111666).

  - drm/vmwgfx: fix a warning due to missing dma_parms
    (bsc#1111666).

  - drm/vmwgfx: Use the backdoor port if the HB port is not
    available (bsc#1111666).

  - EDAC/mc: Fix edac_mc_find() in case no device is found
    (bsc#1114279).

  - ext4: do not delete unlinked inode from orphan list on
    failed truncate (bsc#1140891).

  - failover: allow name change on IFF_UP slave interfaces
    (bsc#1109837).

  - fs: hugetlbfs: fix hwpoison reserve accounting
    (bsc#1139712) 

  - fs/ocfs2: fix race in ocfs2_dentry_attach_lock()
    (bsc#1140889).

  - fs/proc/proc_sysctl.c: Fix a NULL pointer dereference
    (bsc#1140887).

  - fs/proc/proc_sysctl.c: fix NULL pointer dereference in
    put_links (bsc#1140887).

  - ftrace/x86: Remove possible deadlock between
    register_kprobe() and ftrace_run_update_code()
    (bsc#1071995).

  - ftrace/x86: Remove possible deadlock between
    register_kprobe() and ftrace_run_update_code()
    (bsc#1071995 fate#323487).

  - genirq: Prevent use-after-free and work list corruption
    (bsc#1051510).

  - genirq: Respect IRQCHIP_SKIP_SET_WAKE in
    irq_chip_set_wake_parent() (bsc#1051510).

  - genwqe: Prevent an integer overflow in the ioctl
    (bsc#1051510).

  - gpio: omap: fix lack of irqstatus_raw0 for OMAP4
    (bsc#1051510).

  - hugetlbfs: dirty pages as they are added to pagecache
    (git fixes (mm/hugetlbfs)).

  - hugetlbfs: fix kernel BUG at fs/hugetlbfs/inode.c:444!
    (git fixes (mm/hugetlbfs)).

  - hwmon/coretemp: Cosmetic: Rename internal variables to
    zones from packages (jsc#SLE-5454).

  - hwmon/coretemp: Support multi-die/package
    (jsc#SLE-5454).

  - hwmon: (k10temp) 27C Offset needed for Threadripper2
    (FATE#327735).

  - hwmon: (k10temp) Add Hygon Dhyana support (FATE#327735).

  - hwmon: (k10temp) Add support for AMD Ryzen w/ Vega
    graphics (FATE#327735).

  - hwmon: (k10temp) Add support for family 17h
    (FATE#327735).

  - hwmon: (k10temp) Add support for Stoney Ridge and
    Bristol Ridge CPUs (FATE#327735).

  - hwmon: (k10temp) Add support for temperature offsets
    (FATE#327735).

  - hwmon: (k10temp) Add temperature offset for Ryzen 1900X
    (FATE#327735).

  - hwmon: (k10temp) Add temperature offset for Ryzen 2700X
    (FATE#327735).

  - hwmon: (k10temp) Correct model name for Ryzen 1600X
    (FATE#327735).

  - hwmon: (k10temp) Display both Tctl and Tdie
    (FATE#327735).

  - hwmon: (k10temp) Fix reading critical temperature
    register (FATE#327735).

  - hwmon: (k10temp) Make function get_raw_temp static
    (FATE#327735).

  - hwmon: (k10temp) Move chip specific code into probe
    function (FATE#327735).

  - hwmon: (k10temp) Only apply temperature offset if result
    is positive (FATE#327735).

  - hwmon: (k10temp) Support all Family 15h Model 6xh and
    Model 7xh processors (FATE#327735).

  - hwmon: k10temp: Support Threadripper 2920X, 2970WX;
    simplify offset table (FATE#327735).

  - hwmon: (k10temp) Use API function to access System
    Management Network (FATE#327735).

  - hwmon/k10temp, x86/amd_nb: Consolidate shared device IDs
    (FATE#327735).

  - i2c: acorn: fix i2c warning (bsc#1135642).

  - i2c: mlxcpld: Add support for extended transaction
    length for i2c-mlxcpld (bsc#1112374).

  - i2c: mlxcpld: Add support for smbus block read
    transaction (bsc#1112374).

  - i2c: mlxcpld: Allow configurable adapter id for mlxcpld
    (bsc#1112374).

  - i2c: mlxcpld: Fix adapter functionality support callback
    (bsc#1112374).

  - i2c: mlxcpld: Fix wrong initialization order in probe
    (bsc#1112374).

  - i2c: mux: mlxcpld: simplify code to reach the adapter
    (bsc#1112374).

  - i2c-piix4: Add Hygon Dhyana SMBus support (FATE#327735).

  - IB/hfi1: Clear the IOWAIT pending bits when QP is put
    into error state (bsc#1114685 FATE#325854).

  - IB/hfi1: Create inline to get extended headers
    (bsc#1114685 FATE#325854).

  - IB/hfi1: Validate fault injection opcode user input
    (bsc#1114685 FATE#325854).

  - IB/mlx5: Verify DEVX general object type correctly
    (bsc#1103991 FATE#326007).

  - ibmveth: Update ethtool settings to reflect virtual
    properties (bsc#1136157, LTC#177197).

  - input: synaptics - enable SMBus on ThinkPad E480 and
    E580 (bsc#1051510).

  - input: uinput - add compat ioctl number translation for
    UI_*_FF_UPLOAD (bsc#1051510).

  - iommu/amd: Make iommu_disable safer (bsc#1140955).

  - iommu/arm-smmu: Add support for qcom,smmu-v2 variant
    (bsc#1051510).

  - iommu/arm-smmu: Avoid constant zero in TLBI writes
    (bsc#1140956).

  - iommu/arm-smmu-v3: Fix big-endian CMD_SYNC writes
    (bsc#1111666).

  - iommu/arm-smmu-v3: sync the OVACKFLG to PRIQ consumer
    register (bsc#1051510).

  - iommu/arm-smmu-v3: Use explicit mb() when moving cons
    pointer (bsc#1051510).

  - iommu: Fix a leak in iommu_insert_resv_region
    (bsc#1140957).

  - iommu: Use right function to get group for device
    (bsc#1140958).

  - iommu/vt-d: Duplicate iommu_resv_region objects per
    device list (bsc#1140959).

  - iommu/vt-d: Handle PCI bridge RMRR device scopes in
    intel_iommu_get_resv_regions (bsc#1140960).

  - iommu/vt-d: Handle RMRR with PCI bridge device scopes
    (bsc#1140961).

  - iommu/vt-d: Introduce is_downstream_to_pci_bridge helper
    (bsc#1140962).

  - iommu/vt-d: Remove unnecessary rcu_read_locks
    (bsc#1140964).

  - iov_iter: Fix build error without CONFIG_CRYPTO
    (bsc#1111666).

  - ipv6: fib: Do not assume only nodes hold a reference on
    routes (bsc#1138732).

  - irqchip/gic-v3-its: fix some definitions of inner
    cacheability attributes (bsc#1051510).

  - irqchip/mbigen: Do not clear eventid when freeing an MSI
    (bsc#1051510).

  - ixgbe: Avoid NULL pointer dereference with VF on
    non-IPsec hw (bsc#1140228).

  - kabi fixup blk_mq_register_dev() (bsc#1140637).

  - kabi: Mask no_vf_scan in struct pci_dev (jsc#SLE-5803
    FATE#327056).

  - kabi workaround for asus-wmi changes (bsc#1051510).

  - kabi: x86/topology: Add CPUID.1F multi-die/package
    support (jsc#SLE-5454).

  - kabi: x86/topology: Define topology_logical_die_id()
    (jsc#SLE-5454).

  - kvm: svm/avic: fix off-by-one in checking host APIC ID
    (bsc#1140971).

  - kvm: x86: fix return value for reserved EFER
    (bsc#1140992).

  - kvm: x86: Include CPUID leaf 0x8000001e in kvm's
    supported CPUID (bsc#1114279).

  - kvm: x86: Include multiple indices with CPUID leaf
    0x8000001d (bsc#1114279).

  - kvm: x86: Skip EFER vs. guest CPUID checks for
    host-initiated writes (bsc#1140972).

  - libata: Extend quirks for the ST1000LM024 drives with
    NOLPM quirk (bsc#1051510).

  - libceph: assign cookies in linger_submit()
    (bsc#1135897).

  - libceph: check reply num_data_items in
    setup_request_data() (bsc#1135897).

  - libceph: do not consume a ref on pagelist in
    ceph_msg_data_add_pagelist() (bsc#1135897).

  - libceph: enable fallback to ceph_msg_new() in
    ceph_msgpool_get() (bsc#1135897).

  - libceph: introduce alloc_watch_request() (bsc#1135897).

  - libceph: introduce ceph_pagelist_alloc() (bsc#1135897).

  - libceph: preallocate message data items (bsc#1135897).

  - libceph, rbd: add error handling for
    osd_req_op_cls_init() (bsc#1135897). This feature was
    requested for SLE15 but aws reverted in packaging and
    master.

  - libceph, rbd, ceph: move ceph_osdc_alloc_messages()
    calls (bsc#1135897).

  - libnvdimm/bus: Prevent duplicate device_unregister()
    calls (bsc#1139865).

  - libnvdimm, pfn: Fix over-trim in trim_pfn_device()
    (bsc#1140719).

  - mac80211: Do not use stack memory with scatterlist for
    GMAC (bsc#1051510).

  - mac80211: drop robust management frames from unknown TA
    (bsc#1051510).

  - mac80211: handle deauthentication/disassociation from
    TDLS peer (bsc#1051510).

  - media: v4l2-ioctl: clear fields in s_parm (bsc#1051510).

  - mfd: hi655x: Fix regmap area declared size for hi655x
    (bsc#1051510).

  - mISDN: make sure device name is NUL terminated
    (bsc#1051510).

  - mlxsw: core: Add API for QSFP module temperature
    thresholds reading (bsc#1112374).

  - mlxsw: core: Do not use WQ_MEM_RECLAIM for EMAD
    workqueue (bsc#1112374).

  - mlxsw: core: mlxsw: core: avoid -Wint-in-bool-context
    warning (bsc#1112374).

  - mlxsw: core: Move ethtool module callbacks to a common
    location (bsc#1112374).

  - mlxsw: core: Prevent reading unsupported slave address
    from SFP EEPROM (bsc#1112374).

  - mlxsw: pci: Reincrease PCI reset timeout (bsc#1112374).

  - mlxsw: reg: Add Management Temperature Bulk Register
    (bsc#1112374).

  - mlxsw: spectrum_flower: Fix TOS matching (bsc#1112374).

  - mlxsw: spectrum: Move QSFP EEPROM definitions to common
    location (bsc#1112374).

  - mlxsw: spectrum: Put MC TCs into DWRR mode
    (bsc#1112374).

  - mmc: core: complete HS400 before checking status
    (bsc#1111666).

  - mmc: core: Prevent processing SDIO IRQs when the card is
    suspended (bsc#1051510).

  - mm/devm_memremap_pages: introduce devm_memunmap_pages
    (bsc#1103992 FATE#326009).

  - mm: fix race on soft-offlining free huge pages
    (bsc#1139712). 

  - mm: hugetlb: delete dequeue_hwpoisoned_huge_page()
    (bsc#1139712). 

  - mm: hugetlb: prevent reuse of hwpoisoned free hugepages
    (bsc#1139712). 

  - mm: hugetlb: soft-offline: dissolve_free_huge_page()
    return zero on !PageHuge (bsc#bsc#1139712). 

  - mm: hugetlb: soft-offline: dissolve source hugepage
    after successful migration (bsc#1139712). 

  - mm: hugetlb: soft_offline: save compound page order
    before page migration (bsc#1139712) 

  - mm: hwpoison: change PageHWPoison behavior on hugetlb
    pages (bsc#1139712). 

  - mm: hwpoison: dissolve in-use hugepage in unrecoverable
    memory error (bsc#1139712). 

  - mm: hwpoison: introduce idenfity_page_state
    (bsc#1139712). 

  - mm: hwpoison: introduce memory_failure_hugetlb()
    (bsc#1139712). 

  - mm/page_alloc.c: avoid potential NULL pointer
    dereference (git fixes (mm/pagealloc)).

  - mm/page_alloc.c: fix never set ALLOC_NOFRAGMENT flag
    (git fixes (mm/pagealloc)).

  - mm: soft-offline: close the race against page allocation
    (bsc#1139712). 

  - mm: soft-offline: dissolve free hugepage if
    soft-offlined (bsc#1139712). 

  - mm: soft-offline: return -EBUSY if
    set_hwpoison_free_buddy_page() fails (bsc#1139712). 

  - mm/vmscan.c: prevent useless kswapd loops (git fixes
    (mm/vmscan)).

  - module: Fix livepatch/ftrace module text permissions
    race (bsc#1071995 fate#323487).

  - net: core: support XDP generic on stacked devices
    (bsc#1109837).

  - net: do not clear sock->sk early to avoid trouble in
    strparser (bsc#1103990 FATE#326006).

  - net: ena: add ethtool function for changing io queue
    sizes (bsc#1138879).

  - net: ena: add good checksum counter (bsc#1138879).

  - net: ena: add handling of llq max tx burst size
    (bsc#1138879).

  - net: ena: add MAX_QUEUES_EXT get feature admin command
    (bsc#1138879).

  - net: ena: add newline at the end of pr_err prints
    (bsc#1138879).

  - net: ena: add support for changing max_header_size in
    LLQ mode (bsc#1138879).

  - net: ena: allow automatic fallback to polling mode
    (bsc#1138879).

  - net: ena: allow queue allocation backoff when low on
    memory (bsc#1138879).

  - net: ena: arrange ena_probe() function variables in
    reverse christmas tree (bsc#1138879).

  - net: ena: enable negotiating larger Rx ring size
    (bsc#1138879).

  - net: ena: ethtool: add extra properties retrieval via
    get_priv_flags (bsc#1138879).

  - net: ena: Fix bug where ring allocation backoff stopped
    too late (bsc#1138879).

  - net: ena: fix ena_com_fill_hash_function()
    implementation (bsc#1138879).

  - net: ena: fix: Free napi resources when ena_up() fails
    (bsc#1138879).

  - net: ena: fix incorrect test of supported hash function
    (bsc#1138879).

  - net: ena: fix: set freed objects to NULL to avoid
    failing future allocations (bsc#1138879).

  - net: ena: fix swapped parameters when calling
    ena_com_indirect_table_fill_entry (bsc#1138879).

  - net: ena: gcc 8: fix compilation warning (bsc#1138879).

  - net: ena: improve latency by disabling adaptive
    interrupt moderation by default (bsc#1138879).

  - net: ena: make ethtool show correct current and max
    queue sizes (bsc#1138879).

  - net: ena: optimise calculations for CQ doorbell
    (bsc#1138879).

  - net: ena: remove inline keyword from functions in *.c
    (bsc#1138879).

  - net: ena: replace free_tx/rx_ids union with single
    free_ids field in ena_ring (bsc#1138879).

  - net: ena: update driver version from 2.0.3 to 2.1.0
    (bsc#1138879).

  - net: ena: use dev_info_once instead of static variable
    (bsc#1138879).

  - net: ethernet: ti: cpsw_ethtool: fix ethtool ring param
    set (bsc#1130836).

  - net: Fix missing meta data in skb with vlan packet
    (bsc#1109837).

  - net/mlx5: Avoid reloading already removed devices
    (bsc#1103990 FATE#326006).

  - net/mlx5e: Fix ethtool rxfh commands when
    CONFIG_MLX5_EN_RXNFC is disabled (bsc#1103990
    FATE#326006).

  - net/mlx5e: Fix the max MTU check in case of XDP
    (bsc#1103990 FATE#326006).

  - net/mlx5e: Fix use-after-free after xdp_return_frame
    (bsc#1103990 FATE#326006).

  - net/mlx5e: Rx, Check ip headers sanity (bsc#1103990
    FATE#326006).

  - net/mlx5e: Rx, Fixup skb checksum for packets with tail
    padding (bsc#1109837).

  - net/mlx5e: XDP, Fix shifted flag index in RQ bitmap
    (bsc#1103990 FATE#326006).

  - net/mlx5: FPGA, tls, hold rcu read lock a bit longer
    (bsc#1103990 FATE#326006).

  - net/mlx5: FPGA, tls, idr remove on flow delete
    (bsc#1103990 FATE#326006).

  - net/mlx5: Set completion EQs as shared resources
    (bsc#1103991 FATE#326007).

  - net/mlx5: Update pci error handler entries and command
    translation (bsc#1103991 FATE#326007).

  - net: mvpp2: prs: Fix parser range for VID filtering
    (bsc#1098633).

  - net: mvpp2: prs: Use the correct helpers when removing
    all VID filters (bsc#1098633).

  - net: mvpp2: Use strscpy to handle stat strings
    (bsc#1098633).

  - net: phy: marvell10g: report if the PHY fails to boot
    firmware (bsc#1119113 FATE#326472).

  - net/sched: cbs: Fix error path of cbs_module_init
    (bsc#1109837).

  - net/sched: cbs: fix port_rate miscalculation
    (bsc#1109837).

  - net/tls: avoid NULL pointer deref on nskb->sk in
    fallback (bsc#1109837).

  - net/tls: avoid potential deadlock in
    tls_set_device_offload_rx() (bsc#1109837).

  - net: tls, correctly account for copied bytes with
    multiple sk_msgs (bsc#1109837).

  - net/tls: do not copy negative amounts of data in
    reencrypt (bsc#1109837).

  - net/tls: do not ignore netdev notifications if no TLS
    features (bsc#1109837).

  - net/tls: do not leak IV and record seq when offload
    fails (bsc#1109837).

  - net/tls: do not leak partially sent record in device
    mode (bsc#1109837).

  - net/tls: fix build without CONFIG_TLS_DEVICE
    (bsc#1109837).

  - net/tls: fix copy to fragments in reencrypt
    (bsc#1109837).

  - net/tls: fix page double free on TX cleanup
    (bsc#1109837).

  - net/tls: fix refcount adjustment in fallback
    (bsc#1109837).

  - net/tls: fix state removal with feature flags off
    (bsc#1109837).

  - net/tls: fix the IV leaks (bsc#1109837).

  - net/tls: prevent bad memory access in
    tls_is_sk_tx_device_offloaded() (bsc#1109837).

  - net/tls: replace the sleeping lock around RX resync with
    a bit lock (bsc#1109837).

  - net/udp_gso: Allow TX timestamp with UDP GSO
    (bsc#1109837).

  - new primitive: vmemdup_user() (jsc#SLE-4712
    bsc#1136156).

  - nfit/ars: Allow root to busy-poll the ARS state machine
    (bsc#1140814).

  - nfit/ars: Avoid stale ARS results (jsc#SLE-5433).

  - nfit/ars: Introduce scrub_flags (jsc#SLE-5433).

  - nfp: bpf: fix static check error through tightening
    shift amount adjustment (bsc#1109837).

  - nfp: flower: add rcu locks when accessing netdev for
    tunnels (bsc#1109837).

  - nl80211: fix station_info pertid memory leak
    (bsc#1051510).

  - ntp: Allow TAI-UTC offset to be set to zero
    (bsc#1135642).

  - nvme: copy MTFA field from identify controller
    (bsc#1140715).

  - nvme-rdma: fix double freeing of async event data
    (bsc#1120423).

  - nvme-rdma: fix possible double free of controller async
    event buffer (bsc#1120423).

  - ocfs2: try to reuse extent block in dealloc without
    meta_alloc (bsc#1128902).

  - pci: Disable VF decoding before pcibios_sriov_disable()
    updates resources (jsc#SLE-5803).

  - pci: Disable VF decoding before pcibios_sriov_disable()
    updates resources (jsc#SLE-5803 FATE#327056).

  - pci: Do not poll for PME if the device is in D3cold
    (bsc#1051510).

  - pci/IOV: Add flag so platforms can skip VF scanning
    (jsc#SLE-5803).

  - pci/IOV: Add flag so platforms can skip VF scanning
    (jsc#SLE-5803 FATE#327056).

  - pci/IOV: Factor out sriov_add_vfs() (jsc#SLE-5803).

  - pci/IOV: Factor out sriov_add_vfs() (jsc#SLE-5803
    FATE#327056).

  - pci/P2PDMA: fix the gen_pool_add_virt() failure path
    (bsc#1103992).

  - pci/P2PDMA: fix the gen_pool_add_virt() failure path
    (bsc#1103992 FATE#326009).

  - pci: PM: Skip devices in D0 for suspend-to-idle
    (bsc#1051510).

  - pci: rpadlpar: Fix leaked device_node references in
    add/remove paths (bsc#1051510).

  - perf/x86/intel/cstate: Support multi-die/package
    (jsc#SLE-5454).

  - perf/x86/intel/rapl: Cosmetic rename internal variables
    in response to multi-die/pkg support (jsc#SLE-5454).

  - perf/x86/intel/rapl: Support multi-die/package
    (jsc#SLE-5454).

  - perf/x86/intel/uncore: Cosmetic renames in response to
    multi-die/pkg support (jsc#SLE-5454).

  - perf/x86/intel/uncore: Support multi-die/package
    (jsc#SLE-5454).

  - pinctrl/amd: add get_direction handler (bsc#1140463).

  - pinctrl/amd: fix gpio irq level in debugfs
    (bsc#1140463).

  - pinctrl/amd: fix masking of GPIO interrupts
    (bsc#1140463).

  - pinctrl/amd: make functions amd_gpio_suspend and
    amd_gpio_resume static (bsc#1140463).

  - pinctrl/amd: poll InterrupWebRAY bits in
    amd_gpio_irq_set_type (bsc#1140463).

  - pinctrl/amd: poll InterrupWebRAY bits in enable_irq
    (bsc#1140463).

  - platform_data/mlxreg: Add capability field to core
    platform data (bsc#1112374).

  - platform_data/mlxreg: additions for Mellanox watchdog
    driver (bsc#1112374).

  - platform_data/mlxreg: Document fixes for core platform
    data (bsc#1112374).

  - platform/mellanox: Add new ODM system types to
    mlx-platform (bsc#1112374).

  - platform/mellanox: Add TmFifo driver for Mellanox
    BlueField Soc (bsc#1136333 jsc#SLE-4994).

  - platform/x86: asus-wmi: Only Tell EC the OS will handle
    display hotkeys from asus_nb_wmi (bsc#1051510).

  - platform/x86: mlx-platform: Add ASIC hotplug device
    configuration (bsc#1112374).

  - platform/x86: mlx-platform: Add definitions for new
    registers (bsc#1112374).

  - platform/x86: mlx-platform: Add extra CPLD for next
    generation systems (bsc#1112374).

  - platform/x86: mlx-platform: Add LED platform driver
    activation (bsc#1112374).

  - platform/x86: mlx-platform: Add mlxreg-fan platform
    driver activation (bsc#1112374).

  - platform/x86: mlx-platform: Add mlxreg-io platform
    driver activation (bsc#1112374).

  - platform/x86: mlx-platform: Add mlx-wdt platform driver
    activation (bsc#1112374).

  - platform/x86: mlx-platform: Add support for fan
    capability registers (bsc#1112374).

  - platform/x86: mlx-platform: Add support for fan
    direction register (bsc#1112374).

  - platform/x86: mlx-platform: Add support for new VMOD0007
    board name (bsc#1112374).

  - platform/x86: mlx-platform: Add support for tachometer
    speed register (bsc#1112374).

  - platform/x86: mlx-platform: Add UID LED for the next
    generation systems (bsc#1112374).

  - platform/x86: mlx-platform: Allow mlxreg-io driver
    activation for more systems (bsc#1112374).

  - platform/x86: mlx-platform: Allow mlxreg-io driver
    activation for new systems (bsc#1112374).

  - platform/x86: mlx-platform: Change mlxreg-io
    configuration for MSN274x systems (bsc#1112374).

  - platform/x86: mlx-platform: Convert to use SPDX
    identifier (bsc#1112374).

  - platform/x86: mlx-platform: Fix access mode for fan_dir
    attribute (bsc#1112374).

  - platform/x86: mlx-platform: Fix copy-paste error in
    mlxplat_init() (bsc#1112374).

  - platform/x86: mlx-platform: Fix LED configuration
    (bsc#1112374).

  - platform/x86: mlx-platform: Fix tachometer registers
    (bsc#1112374).

  - platform/x86: mlx-platform: Remove unused define
    (bsc#1112374).

  - platform/x86: mlx-platform: Rename new systems product
    names (bsc#1112374).

  - PM: ACPI/PCI: Resume all devices during hibernation
    (bsc#1111666).

  - powercap/intel_rapl: Simplify rapl_find_package()
    (jsc#SLE-5454).

  - powercap/intel_rapl: Support multi-die/package
    (jsc#SLE-5454).

  - powercap/intel_rapl: Update RAPL domain name and debug
    messages (jsc#SLE-5454).

  - powerpc/perf: Add PM_LD_MISS_L1 and PM_BR_2PATH to
    power9 event list (bsc#1137728, LTC#178106).

  - powerpc/perf: Add POWER9 alternate PM_RUN_CYC and
    PM_RUN_INST_CMPL events (bsc#1137728, LTC#178106).

  - powerpc/rtas: retry when cpu offline races with
    suspend/migration (bsc#1140428, LTC#178808).

  - ppc64le: enable CONFIG_PPC_DT_CPU_FTRS (jsc#SLE-7159).

  - ppp: mppe: Add softdep to arc4 (bsc#1088047).

  - ptrace: Fix -$gt;ptracer_cred handling for
    PTRACE_TRACEME (git-fixes).

  - ptrace: restore smp_rmb() in __ptrace_may_access()
    (git-fixes).

  - pwm: stm32: Use 3 cells ->of_xlate() (bsc#1111666).

  - qedi: Use hwfns and affin_hwfn_idx to get MSI-X vector
    index (jsc#SLE-4693 bsc#1136462).

  - qmi_wwan: add network device usage statistics for qmimux
    devices (bsc#1051510).

  - qmi_wwan: add support for QMAP padding in the RX path
    (bsc#1051510).

  - qmi_wwan: avoid RCU stalls on device disconnect when in
    QMAP mode (bsc#1051510).

  - qmi_wwan: extend permitted QMAP mux_id value range
    (bsc#1051510).

  - qmi_wwan: Fix out-of-bounds read (bsc#1111666).

  - rapidio: fix a NULL pointer dereference when
    create_workqueue() fails (bsc#1051510).

  - RAS/CEC: Convert the timer callback to a workqueue
    (bsc#1114279).

  - RAS/CEC: Fix binary search function (bsc#1114279).

  - rbd: do not assert on writes to snapshots (bsc#1137985
    bsc#1138681).

  - rdma/ipoib: Allow user space differentiate between valid
    dev_port (bsc#1103992).

  - rdma/ipoib: Allow user space differentiate between valid
    dev_port (bsc#1103992 FATE#326009).

  - rdma/mlx5: Do not allow the user to write to the clock
    page (bsc#1103991).

  - rdma/mlx5: Do not allow the user to write to the clock
    page (bsc#1103991 FATE#326007).

  - rdma/mlx5: Initialize roce port info before multiport
    master init (bsc#1103991).

  - rdma/mlx5: Initialize roce port info before multiport
    master init (bsc#1103991 FATE#326007).

  - rdma/mlx5: Use rdma_user_map_io for mapping BAR pages
    (bsc#1103992).

  - rdma/mlx5: Use rdma_user_map_io for mapping BAR pages
    (bsc#1103992 FATE#326009).

  - Refresh
    patches.fixes/scsi-Introduce-scsi_start_queue.patch
    (bsc#1119532).

  - regulator: s2mps11: Fix buck7 and buck8 wrong voltages
    (bsc#1051510).

  - Replace the bluetooth fix with the upstream commit
    (bsc#1135556)

  - Reshuffle patches to match series_sort.py

  - Revert 'net: ena: ethtool: add extra properties
    retrieval via get_priv_flags' (bsc#1138879).

  - Revert 'net/mlx5e: Enable reporting checksum unnecessary
    also for L3 packets' (bsc#1103990).

  - Revert 'net/mlx5e: Enable reporting checksum unnecessary
    also for L3 packets' (bsc#1103990 FATE#326006).

  - Revert 'Revert 'Drop multiversion(kernel) from the KMP
    template ()''

  - Revert 'Revert 'Drop multiversion(kernel) from the KMP
    template (fate#323189)

  - Revert 's390/jump_label: Use 'jdd' constraint on gcc9
    (bsc#1138589).' This broke the build with older gcc
    instead.

  - Revert 'Sign non-x86 kernels when possible
    (boo#1134303)' This reverts commit
    bac621c6704610562ebd9e74ae5ad85ca8025681. We do not have
    reports of this working with all ARM architectures in
    all cases (boot, kexec, ..) so revert for now.

  - Revert 'svm: Fix AVIC incomplete IPI emulation'
    (bsc#1140133).

  - rpm/package-descriptions: fix typo in kernel-azure

  - rpm/post.sh: correct typo in err msg (bsc#1137625)

  - s390/dasd: fix using offset into zero size array error
    (bsc#1051510).

  - s390/jump_label: Use 'jdd' constraint on gcc9
    (bsc#1138589).

  - s390/pci: improve bar check (jsc#SLE-5803).

  - s390/pci: improve bar check (jsc#SLE-5803 FATE#327056).

  - s390/pci: map IOV resources (jsc#SLE-5803).

  - s390/pci: map IOV resources (jsc#SLE-5803 FATE#327056).

  - s390/pci: skip VF scanning (jsc#SLE-5803).

  - s390/pci: skip VF scanning (jsc#SLE-5803 FATE#327056).

  - s390/qeth: fix race when initializing the IP address
    table (bsc#1051510).

  - s390/qeth: fix VLAN attribute in bridge_hostnotify udev
    event (bsc#1051510).

  - s390/setup: fix early warning messages (bsc#1051510).

  - s390/virtio: handle find on invalid queue gracefully
    (bsc#1051510).

  - sbitmap: fix improper use of smp_mb__before_atomic()
    (bsc#1140658).

  - sched/topology: Improve load balancing on AMD EPYC
    (bsc#1137366).

  - scripts/git_sort/git_sort.py: add djbw/nvdimm
    nvdimm-pending.

  - scripts/git_sort/git_sort.py: add nvdimm/libnvdimm-fixes

  - scripts/git_sort/git_sort.py: drop old scsi branches

  - scsi: aacraid: change event_wait to a completion
    (jsc#SLE-4710 bsc#1136161).

  - scsi: aacraid: change wait_sem to a completion
    (jsc#SLE-4710 bsc#1136161).

  - scsi: aacraid: clean up some indentation and formatting
    issues (jsc#SLE-4710 bsc#1136161).

  - scsi: aacraid: Mark expected switch fall-through
    (jsc#SLE-4710 bsc#1136161).

  - scsi: aacraid: Mark expected switch fall-throughs
    (jsc#SLE-4710 bsc#1136161).

  - scsi: be2iscsi: be_iscsi: Mark expected switch
    fall-through (jsc#SLE-4721 bsc#1136264).

  - scsi: be2iscsi: be_main: Mark expected switch
    fall-through (jsc#SLE-4721 bsc#1136264).

  - scsi: be2iscsi: fix spelling mistake 'Retreiving' -gt;
    'Retrieving' (jsc#SLE-4721 bsc#1136264).

  - scsi: be2iscsi: lpfc: fix typo (jsc#SLE-4721
    bsc#1136264).

  - scsi: be2iscsi: remove unused variable dmsg
    (jsc#SLE-4721 bsc#1136264).

  - scsi: be2iscsi: switch to generic DMA API (jsc#SLE-4721
    bsc#1136264).

  - scsi: core: add new RDAC LENOVO/DE_Series device
    (bsc#1132390).

  - scsi: csiostor: csio_wr: mark expected switch
    fall-through (jsc#SLE-4679 bsc#1136343).

  - scsi: csiostor: drop serial_number usage (jsc#SLE-4679
    bsc#1136343).

  - scsi: csiostor: fix calls to dma_set_mask_and_coherent()
    (jsc#SLE-4679 bsc#1136343).

  - scsi: csiostor: fix incorrect dma device in case of
    vport (jsc#SLE-4679 bsc#1136343).

  - scsi: csiostor: fix missing data copy in
    csio_scsi_err_handler() (jsc#SLE-4679 bsc#1136343).

  - scsi: csiostor: fix NULL pointer dereference in
    csio_vport_set_state() (jsc#SLE-4679 bsc#1136343).

  - scsi: csiostor: no need to check return value of
    debugfs_create functions (jsc#SLE-4679 bsc#1136343).

  - scsi: csiostor: Remove set but not used variable 'pln'
    (jsc#SLE-4679 bsc#1136343).

  - scsi: hpsa: bump driver version (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: check for lv removal (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: clean up two indentation issues
    (jsc#SLE-4712 bsc#1136156).

  - scsi: hpsa: correct device id issues (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: correct device resets (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: correct ioaccel2 chaining (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: correct simple mode (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: fix an uninitialized read and dereference of
    pointer dev (jsc#SLE-4712 bsc#1136156).

  - scsi: hpsa: mark expected switch fall-throughs
    (jsc#SLE-4712 bsc#1136156).

  - scsi: hpsa: remove timeout from TURs (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: switch to generic DMA API (jsc#SLE-4712
    bsc#1136156).

  - scsi: hpsa: Use vmemdup_user to replace the open code
    (jsc#SLE-4712 bsc#1136156).

  - scsi: megaraid_sas: Add support for DEVICE_LIST DCMD in
    driver (bsc#1136271).

  - scsi: megaraid_sas: correct an info message
    (bsc#1136271).

  - scsi: megaraid_sas: driver version update (bsc#1136271).

  - scsi: megaraid_sas: Retry reads of outbound_intr_status
    reg (bsc#1136271).

  - scsi: megaraid_sas: Rework code to get PD and LD list
    (bsc#1136271).

  - scsi: megaraid_sas: Rework device add code in AEN path
    (bsc#1136271).

  - scsi: megaraid_sas: Update structures for
    HOST_DEVICE_LIST DCMD (bsc#1136271).

  - scsi: mpt3sas: Add Atomic RequestDescriptor support on
    Aero (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Add flag high_iops_queues
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Add missing breaks in switch statements
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Add support for ATLAS PCIe switch
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Add support for NVMe Switch Adapter
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Affinity high iops queues IRQs to local
    node (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: change _base_get_msix_index prototype
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Enable interrupt coalescing on high iops
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: fix indentation issue
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Fix kernel panic during expander reset
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Fix typo in request_desript_type
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: function pointers of request descriptor
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Improve the threshold value and introduce
    module param (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Introduce perf_mode module parameter
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Irq poll to avoid CPU hard lockups
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Load balance to improve performance and
    avoid soft lockups (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Rename mpi endpoint device ID macro
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: save and use MSI-X index for posting RD
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: simplify interrupt handler
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Update driver version to 27.102.00.00
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Update driver version to 29.100.00.00
    (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Update mpt3sas driver version to
    28.100.00.00 (bsc#1125703,jsc#SLE-4717).

  - scsi: mpt3sas: Use high iops queues under some
    circumstances (bsc#1125703,jsc#SLE-4717).

  - scsi: qedi: add module param to set ping packet size
    (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: Add packet filter in light L2 Rx path
    (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: Check for session online before getting
    iSCSI TLV data (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: Cleanup redundant QEDI_PAGE_SIZE macro
    definition (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: Fix spelling mistake 'OUSTANDING' ->
    'OUTSTANDING' (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: Move LL2 producer index processing in BH
    (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: remove set but not used variables 'cdev' and
    'udev' (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: Replace PAGE_SIZE with QEDI_PAGE_SIZE
    (jsc#SLE-4693 bsc#1136462).

  - scsi: qedi: Update driver version to 8.33.0.21
    (jsc#SLE-4693 bsc#1136462).

  - scsi: qla2xxx: Fix abort handling in
    tcm_qla2xxx_write_pending() (bsc#1140727).

  - scsi: qla2xxx: Fix FC-AL connection target discovery
    (bsc#1094555).

  - scsi: qla2xxx: Fix incorrect region-size setting in
    optrom SYSFS routines (bsc#1140728).

  - scsi: qla2xxx: Fix N2N target discovery with Local loop
    (bsc#1094555).

  - scsi: target/iblock: Fix overrun in WRITE SAME emulation
    (bsc#1140424).

  - scsi: target/iblock: Fix overrun in WRITE SAME emulation
    (bsc#1140424).

  - scsi: vmw_pscsi: Fix use-after-free in
    pvscsi_queue_lck() (bsc#1135296).

  - scsi: zfcp: fix missing zfcp_port reference put on
    -EBUSY from port_remove (bsc#1051510).

  - scsi: zfcp: fix rport unblock if deleted SCSI devices on
    Scsi_Host (bsc#1051510).

  - scsi: zfcp: fix scsi_eh host reset with port_forced ERP
    for non-NPIV FCP devices (bsc#1051510).

  - scsi: zfcp: fix to prevent port_remove with pure auto
    scan LUNs (only sdevs) (bsc#1051510).

  - signal/ptrace: Do not leak uninitialized kernel memory
    with PTRACE_PEEK_SIGINFO (git-fixes).

  - smb3: Fix endian warning (bsc#1137884).

  - soc: mediatek: pwrap: Zero initialize rdata in
    pwrap_init_cipher (bsc#1051510).

  - soc: rockchip: Set the proper PWM for rk3288
    (bsc#1051510).

  - sort patches to proper position

  - squash
    patches.fixes/tcp-fix-fack_count-accounting-on-tcp_shift
    _skb_data.patch into
    patches.fixes/tcp-limit-payload-size-of-sacked-skbs.patc
    h to match what stable backports do

  - staging: comedi: ni_mio_common: Fix divide-by-zero for
    DIO cmdtest (bsc#1051510).

  - staging:iio:ad7150: fix threshold mode config bit
    (bsc#1051510).

  - supported.conf: added mlxbf_tmfifo (bsc#1136333
    jsc#SLE-4994)

  - svm: Add warning message for AVIC IPI invalid target
    (bsc#1140133).

  - svm: Fix AVIC incomplete IPI emulation (bsc#1140133).

  - sysctl: handle overflow in proc_get_long (bsc#1051510).

  - thermal: rcar_gen3_thermal: disable interrupt in .remove
    (bsc#1051510).

  - thermal/x86_pkg_temp_thermal: Cosmetic: Rename internal
    variables to zones from packages (jsc#SLE-5454).

  - thermal/x86_pkg_temp_thermal: Support multi-die/package
    (jsc#SLE-5454).

  - tmpfs: fix link accounting when a tmpfile is linked in
    (bsc#1051510).

  - tmpfs: fix uninitialized return value in shmem_link
    (bsc#1051510).

  - tools: bpftool: fix infinite loop in map create
    (bsc#1109837).

  - topology: Create core_cpus and die_cpus sysfs attributes
    (jsc#SLE-5454).

  - topology: Create package_cpus sysfs attribute
    (jsc#SLE-5454).

  - tracing/snapshot: Resize spare buffer if size changed
    (bsc#1140726).

  - tty: max310x: Fix external crystal register setup
    (bsc#1051510).

  - typec: tcpm: fix compiler warning about stupid things
    (git-fixes).

  - usb: chipidea: udc: workaround for endpoint conflict
    issue (bsc#1135642).

  - usb: dwc2: host: Fix wMaxPacketSize handling (fix webcam
    regression) (bsc#1135642).

  - usb: Fix chipmunk-like voice when using Logitech C270
    for recording audio (bsc#1051510).

  - usbnet: ipheth: fix racing condition (bsc#1051510).

  - usb: serial: fix initial-termios handling (bsc#1135642).

  - usb: serial: option: add support for Simcom
    SIM7500/SIM7600 RNDIS mode (bsc#1051510).

  - usb: serial: option: add Telit 0x1260 and 0x1261
    compositions (bsc#1051510).

  - usb: serial: pl2303: add Allied Telesis VT-Kit3
    (bsc#1051510).

  - usb: serial: pl2303: fix tranceiver suspend mode
    (bsc#1135642).

  - usb: usb-storage: Add new ID to ums-realtek
    (bsc#1051510).

  - usb: xhci: avoid NULL pointer deref when bos field is
    NULL (bsc#1135642).

  - vfio: ccw: only free cp on final interrupt
    (bsc#1051510).

  - vlan: disable SIOCSHWTSTAMP in container (bsc#1051510).

  - x86/amd_nb: Add support for Raven Ridge CPUs
    (FATE#327735).

  - x86/CPU/AMD: Do not force the CPB cap when running under
    a hypervisor (bsc#1114279).

  - x86/cpufeatures: Carve out CQM features retrieval
    (jsc#SLE-5382).

  - x86/cpufeatures: Combine word 11 and 12 into a new
    scattered features word (jsc#SLE-5382). This changes
    definitions of some bits, but they are intended to be
    used only by the core, so hopefully, no KMP uses the
    definitions.

  - x86/cpufeatures: Enumerate the new AVX512 BFLOAT16
    instructions (jsc#SLE-5382).

  - x86/cpufeatures: Enumerate user wait instructions
    (jsc#SLE-5187).

  - x86/CPU/hygon: Fix phys_proc_id calculation logic for
    multi-die processors (fate#327735).

  - x86/mce: Fix machine_check_poll() tests for error types
    (bsc#1114279).

  - x86/microcode, cpuhotplug: Add a microcode loader CPU
    hotplug callback (bsc#1114279).

  - x86/microcode: Fix microcode hotplug state
    (bsc#1114279).

  - x86/microcode: Fix the ancient deprecated microcode
    loading method (bsc#1114279).

  - x86/mm/mem_encrypt: Disable all instrumentation for
    early SME setup (bsc#1114279).

  - x86/smpboot: Rename match_die() to match_pkg()
    (jsc#SLE-5454).

  - x86/speculation/mds: Revert CPU buffer clear on double
    fault exit (bsc#1114279).

  - x86/topology: Add CPUID.1F multi-die/package support
    (jsc#SLE-5454).

  - x86/topology: Create topology_max_die_per_package()
    (jsc#SLE-5454).

  - x86/topology: Define topology_die_id() (jsc#SLE-5454).

  - x86/topology: Define topology_logical_die_id()
    (jsc#SLE-5454).

  - x86/umwait: Add sysfs interface to control umwait C0.2
    state (jsc#SLE-5187).

  - x86/umwait: Add sysfs interface to control umwait
    maximum time (jsc#SLE-5187).

  - x86/umwait: Initialize umwait control values
    (jsc#SLE-5187).

  - xdp: check device pointer before clearing (bsc#1109837).

  - {nl,mac}80211: allow 4addr AP operation on crypto
    controlled devices (bsc#1051510)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140992"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.10.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
