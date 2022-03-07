#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1716.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126884);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2018-16871", "CVE-2018-20836", "CVE-2019-10126", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11599", "CVE-2019-12614");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1716)");
  script_summary(english:"Check for the openSUSE-2019-1716 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 was updated to receive various security and
bugfixes.

The following security bugs were fixed :

  - CVE-2019-10638: A device can be tracked by an attacker
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

  - CVE-2018-20836: There was a race condition in
    smp_task_timedout() and smp_task_done() in
    drivers/scsi/libsas/sas_expander.c, leading to a
    use-after-free (bnc#1134395).

  - CVE-2019-10126: A heap based buffer overflow in
    mwifiex_uap_parse_tail_ies function in
    drivers/net/wireless/marvell/mwifiex/ie.c might lead to
    memory corruption and possibly other consequences
    (bnc#1136935).

  - CVE-2019-11599: The coredump implementation in the Linux
    kernel did not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs,
    which allowed local users to obtain sensitive
    information, cause a denial of service, or possibly have
    unspecified other impact by triggering a race condition
    with mmget_not_zero or get_task_mm calls. This is
    related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and
    drivers/infiniband/core/uverbs_main.c (bnc#1131645
    1133738).

  - CVE-2019-12614: An issue was discovered in
    dlpar_parse_cc_property in
    arch/powerpc/platforms/pseries/dlpar.c where there was
    an unchecked kstrdup of prop->name, which might allow an
    attacker to cause a denial of service (NULL pointer
    dereference and system crash) (bnc#1137194).

  - CVE-2018-16871: A flaw was found in NFS where an
    attacker who is able to mount an exported NFS filesystem
    was able to trigger a NULL pointer dereference by an
    invalid NFS sequence. (bnc#1137103).

The following non-security bugs were fixed :

  - 6lowpan: Off by one handling ->nexthdr (bsc#1051510).

  - added De0-Nanos-SoC board support (and others based on
    Altera SOC).

  - Add sample kernel-default-base spec file (FATE#326579,
    jsc#SLE-4117, jsc#SLE-3853, bsc#1128910).

  - Add sample kernel-default-base spec file (jsc#SLE-4117,
    jsc#SLE-3853, bsc#1128910).

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

  - alsa: usb-audio: fix sign unintended sign extension on
    left shifts (bsc#1051510).

  - apparmor: enforce nullbyte at end of tag string
    (bsc#1051510).

  - audit: fix a memory leak bug (bsc#1051510).

  - ax25: fix inconsistent lock state in ax25_destroy_timer
    (bsc#1051510).

  - blk-mq: free hw queue's resource in hctx's release
    handler (bsc#1140637).

  - block: Fix a NULL pointer dereference in
    generic_make_request() (bsc#1139771).

  - bluetooth: Fix faulty expression for minimum encryption
    key size check (bsc#1140328).

  - can: af_can: Fix error path of can_init() (bsc#1051510).

  - can: flexcan: fix timeout when set small bitrate
    (bsc#1051510).

  - can: purge socket error queue on sock destruct
    (bsc#1051510).

  - ceph: flush dirty inodes before proceeding with remount
    (bsc#1140405).

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

  - device core: Consolidate locking and unlocking of parent
    and device (bsc#1106383).

  - dmaengine: imx-sdma: remove BD_INTR for channel0
    (bsc#1051510).

  - dm, dax: Fix detection of DAX support (bsc#1139782).

  - doc: Cope with the deprecation of AutoReporter
    (bsc#1051510).

  - Do not provide kernel-default from kernel-default-base
    (boo#1132154, bsc#1106751).

  - Do not provide kernel-default-srchash from
    kernel-default-base.

  - Do not restrict NFSv4.2 on openSUSE (bsc#1138719).

  - driver core: Establish order of operations for
    device_add and device_del via bitflag (bsc#1106383).

  - driver core: Probe devices asynchronously instead of the
    driver (bsc#1106383).

  - drivers/base: Introduce kill_device() (bsc#1139865).

  - drivers/base: kABI fixes for struct device_private
    (bsc#1106383).

  - drivers: misc: fix out-of-bounds access in function
    param_set_kgdbts_var (bsc#1051510).

  - drivers/rapidio/devices/rio_mport_cdev.c: fix resource
    leak in error handling path in 'rio_dma_transfer()'
    (bsc#1051510).

  - drivers/rapidio/rio_cm.c: fix potential oops in
    riocm_ch_listen() (bsc#1051510).

  - drivers: thermal: tsens: Do not print error message on
    -EPROBE_DEFER (bsc#1051510).

  - drm/arm/hdlcd: Allow a bit of clock tolerance
    (bsc#1051510).

  - drm/i915/gvt: ignore unexpected pvinfo write
    (bsc#1051510).

  - EDAC/mc: Fix edac_mc_find() in case no device is found
    (bsc#1114279).

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
    ().

  - hwmon/k10temp, x86/amd_nb: Consolidate shared device IDs
    (FATE#327735).

  - i2c: acorn: fix i2c warning (bsc#1135642).

  - i2c-piix4: Add Hygon Dhyana SMBus support (FATE#327735).

  - ibmveth: Update ethtool settings to reflect virtual
    properties (bsc#1136157, LTC#177197).

  - input: synaptics - enable SMBus on ThinkPad E480 and
    E580 (bsc#1051510).

  - input: uinput - add compat ioctl number translation for
    UI_*_FF_UPLOAD (bsc#1051510).

  - Install extra rpm scripts for kernel subpackaging
    (FATE#326579, jsc#SLE-4117, jsc#SLE-3853, bsc#1128910).

  - Install extra rpm scripts for kernel subpackaging
    (jsc#SLE-4117, jsc#SLE-3853, bsc#1128910).

  - kabi fixup blk_mq_register_dev() (bsc#1140637).

  - kabi: x86/topology: Add CPUID.1F multi-die/package
    support (jsc#SLE-5454).

  - kabi: x86/topology: Define topology_logical_die_id()
    (jsc#SLE-5454).

  - kvm: x86: Include CPUID leaf 0x8000001e in kvm's
    supported CPUID (bsc#1114279).

  - kvm: x86: Include multiple indices with CPUID leaf
    0x8000001d (bsc#1114279).

  - libata: Extend quirks for the ST1000LM024 drives with
    NOLPM quirk (bsc#1051510).

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

  - mISDN: make sure device name is NUL terminated
    (bsc#1051510).

  - mmc: core: Prevent processing SDIO IRQs when the card is
    suspended (bsc#1051510).

  - module: Fix livepatch/ftrace module text permissions
    race (bsc#1071995).

  - module: Fix livepatch/ftrace module text permissions
    race (bsc#1071995 fate#323487).

  - net: mvpp2: prs: Fix parser range for VID filtering
    (bsc#1098633).

  - net: mvpp2: prs: Use the correct helpers when removing
    all VID filters (bsc#1098633).

  - net: mvpp2: Use strscpy to handle stat strings
    (bsc#1098633).

  - nfit/ars: Allow root to busy-poll the ARS state machine
    (bsc#1140814).

  - nfit/ars: Avoid stale ARS results (jsc#SLE-5433).

  - nfit/ars: Introduce scrub_flags (jsc#SLE-5433).

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

  - ppp: mppe: Add softdep to arc4 (bsc#1088047).

  - qmi_wwan: add network device usage statistics for qmimux
    devices (bsc#1051510).

  - qmi_wwan: add support for QMAP padding in the RX path
    (bsc#1051510).

  - qmi_wwan: avoid RCU stalls on device disconnect when in
    QMAP mode (bsc#1051510).

  - qmi_wwan: extend permitted QMAP mux_id value range
    (bsc#1051510).

  - rapidio: fix a NULL pointer dereference when
    create_workqueue() fails (bsc#1051510).

  - ras/CEC: Convert the timer callback to a workqueue
    (bsc#1114279).

  - ras/CEC: Fix binary search function (bsc#1114279).

  - Refresh
    patches.fixes/scsi-Introduce-scsi_start_queue.patch
    (bsc#1119532).

  - Remove the previous subpackage infrastructure. This
    partially reverts commit
    9b3ca32c11854156b2f950ff5e26131377d8445e ('Add
    kernel-subpackage-build.spec (FATE#326579).')

  - Replace the bluetooth fix with the upstream commit
    (bsc#1135556)

  - Revert 'Drop multiversion(kernel) from the KMP template
    ()' (bsc#1109137).

  - Revert 'Drop multiversion(kernel) from the KMP template
    (fate#323189)' (bsc#1109137). This reverts commit
    71504d805c1340f68715ad41958e5ef35da2c351.

  - Revert 'KMPs: obsolete older KMPs of the same flavour
    (bsc#1127155, bsc#1109137).'

  - Revert 'KMPs: provide and conflict a kernel version
    specific KMP name'

  - Revert 'Revert 'Drop multiversion(kernel) from the KMP
    template ()''

  - Revert 'Revert 'Drop multiversion(kernel) from the KMP
    template (fate#323189)'' This feature was requested for
    SLE15 but aws reverted in packaging and master.

  - Revert 's390/jump_label: Use 'jdd' constraint on gcc9
    (bsc#1138589).'

  - Revert 'Sign non-x86 kernels when possible
    (boo#1134303)' This reverts commit
    bac621c6704610562ebd9e74ae5ad85ca8025681.

  - Revert 'svm: Fix AVIC incomplete IPI emulation'
    (bsc#1140133).

  - rpm: Add arm64 dtb-allwinner subpackage 4.10 added
    arch/arm64/boot/dts/allwinner/.

  - rpm: Add arm64 dtb-zte subpackage 4.9 added
    arch/arm64/boot/dts/zte/.

  - rpm/kernel-binary.spec.in: Add back kernel-binary-base
    subpackage (jsc#SLE-3853).

  - rpm/kernel-binary.spec.in: Build livepatch support in
    SUSE release projects (bsc#1124167).

  - rpm/kernel-subpackage-build: handle arm kernel zImage.

  - rpm/kernel-subpackage-spec: only provide firmware
    actually present in subpackage.

  - rpm/package-descriptions: fix typo in kernel-azure

  - rpm/post.sh: correct typo in err msg (bsc#1137625)

  - s390/dasd: fix using offset into zero size array error
    (bsc#1051510).

  - s390/jump_label: Use 'jdd' constraint on gcc9
    (bsc#1138589).

  - s390/qeth: fix race when initializing the IP address
    table (bsc#1051510).

  - s390/qeth: fix VLAN attribute in bridge_hostnotify udev
    event (bsc#1051510).

  - s390/setup: fix early warning messages (bsc#1051510).

  - s390/virtio: handle find on invalid queue gracefully
    (bsc#1051510).

  - sbitmap: fix improper use of smp_mb__before_atomic()
    (bsc#1140658).

  - scripts/git_sort/git_sort.py: add djbw/nvdimm
    nvdimm-pending.

  - scripts/git_sort/git_sort.py: add nvdimm/libnvdimm-fixes

  - scsi: core: add new RDAC LENOVO/DE_Series device
    (bsc#1132390).

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

  - smb3: Fix endian warning (bsc#1137884).

  - soc: mediatek: pwrap: Zero initialize rdata in
    pwrap_init_cipher (bsc#1051510).

  - soc: rockchip: Set the proper PWM for rk3288
    (bsc#1051510).

  - staging: comedi: ni_mio_common: Fix divide-by-zero for
    DIO cmdtest (bsc#1051510).

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

  - topology: Create core_cpus and die_cpus sysfs attributes
    (jsc#SLE-5454).

  - topology: Create package_cpus sysfs attribute
    (jsc#SLE-5454).

  - tracing/snapshot: Resize spare buffer if size changed
    (bsc#1140726).

  - Trim build dependencies of sample subpackage spec file
    (FATE#326579, jsc#SLE-4117, jsc#SLE-3853, bsc#1128910).

  - Trim build dependencies of sample subpackage spec file
    (jsc#SLE-4117, jsc#SLE-3853, bsc#1128910).

  - tty: max310x: Fix external crystal register setup
    (bsc#1051510).

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

  - x86/amd_nb: Add support for Raven Ridge CPUs ().

  - x86/amd_nb: Add support for Raven Ridge CPUs
    (FATE#327735).

  - x86/CPU/AMD: Do not force the CPB cap when running under
    a hypervisor (bsc#1114279).

  - x86/cpufeatures: Carve out CQM features retrieval
    (jsc#SLE-5382).

  - x86/cpufeatures: Combine word 11 and 12 into a new
    scattered features word (jsc#SLE-5382).

  - x86/cpufeatures: Enumerate the new AVX512 BFLOAT16
    instructions (jsc#SLE-5382).

  - x86/CPU/hygon: Fix phys_proc_id calculation logic for
    multi-die processors ().

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
    (jsc#SLE-5454)."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132154"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136157"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139782"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/19");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.67.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.67.1") ) flag++;

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
