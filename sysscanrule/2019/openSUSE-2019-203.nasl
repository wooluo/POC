#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-203.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122303);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-20669", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-203)");
  script_summary(english:"Check for the openSUSE-2019-203 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2019-3459,CVE-2019-3460: Two information leaks in
    the bluetooth stack were fixed. (bnc#1120758).

  - CVE-2019-7221: A use-after-free in the KVM nVMX hrtimer
    was fixed. (bnc#1124732).

  - CVE-2019-7222: A information leak in exception handling
    in KVM could be used to expose host memory to guests.
    (bnc#1124735).

  - CVE-2019-6974: A use-after-free in the KVM device
    control API was fixed. (bnc#1124728).

  - CVE-2018-20669: Missing access control checks in ioctl
    of gpu/drm/i915 driver were fixed which might have lead
    to information leaks. (bnc#1122971).

The following non-security bugs were fixed :

  - 6lowpan: iphc: reset mac_header after decompress to fix
    panic (bsc#1051510).

  - 9p: clear dangling pointers in p9stat_free
    (bsc#1051510).

  - 9p locks: fix glock.client_id leak in do_lock
    (bsc#1051510).

  - 9p/net: put a lower bound on msize (bsc#1051510).

  - acpi/nfit: Block function zero DSMs (bsc#1051510).

  - acpi, nfit: Fix Address Range Scrub completion tracking
    (bsc#1124969).

  - acpi/nfit: Fix command-supported detection
    (bsc#1051510).

  - acpi/nfit: Fix race accessing memdev in
    nfit_get_smbios_id() (bsc#1122662).

  - acpi/nfit: Fix user-initiated ARS to be 'ARS-long'
    rather than 'ARS-short' (bsc#1124969).

  - ACPI: power: Skip duplicate power resource references in
    _PRx (bsc#1051510).

  - Add delay-init quirk for Corsair K70 RGB keyboards
    (bsc#1087092).

  - af_iucv: Move sockaddr length checks to before accessing
    sa_family in bind and connect handlers (bsc#1051510).

  - alsa: bebob: fix model-id of unit for Apogee Ensemble
    (bsc#1051510).

  - alsa: compress: Fix stop handling on compressed capture
    streams (bsc#1051510).

  - alsa: hda - Add mute LED support for HP ProBook 470 G5
    (bsc#1051510).

  - alsa: hda/ca0132 - Fix build error without CONFIG_PCI
    (bsc#1051510).

  - alsa: hda/realtek - Fixed hp_pin no value (bsc#1051510).

  - alsa: hda/realtek - Fix lose hp_pins for disable auto
    mute (bsc#1051510).

  - alsa: hda/realtek - Use a common helper for hp pin
    reference (bsc#1051510).

  - alsa: hda - Serialize codec registrations (bsc#1122944).

  - alsa: hda - Use standard device registration for beep
    (bsc#1122944).

  - alsa: oxfw: add support for APOGEE duet FireWire
    (bsc#1051510).

  - alsa: usb-audio: Add Opus #3 to quirks for native DSD
    support (bsc#1051510).

  - alsa: usb-audio: Add support for new T+A USB DAC
    (bsc#1051510).

  - amd-xgbe: Fix mdio access for non-zero ports and clause
    45 PHYs (bsc#1122927).

  - arm: 8802/1: Call syscall_trace_exit even when system
    call skipped (bsc#1051510).

  - arm: 8814/1: mm: improve/fix ARM v7_dma_inv_range()
    unaligned address handling (bsc#1051510).

  - arm: 8815/1: V7M: align v7m_dma_inv_range() with v7
    counterpart (bsc#1051510).

  - arm/arm64: kvm:vgic: Force VM halt when changing the
    active state of GICv3 PPIs/SGIs (bsc#1051510).

  - arm: cns3xxx: Fix writing to wrong PCI config registers
    after alignment (bsc#1051510).

  - arm: cns3xxx: Use actual size reads for PCIe
    (bsc#1051510).

  - arm: imx: update the cpu power up timing setting on
    i.mx6sx (bsc#1051510).

  - arm: kvm:Fix VTTBR_BADDR_MASK BUG_ON off-by-one
    (bsc#1051510).

  - arm: mmp/mmp2: fix cpu_is_mmp2() on mmp2-dt
    (bsc#1051510).

  - arm: OMAP1: ams-delta: Fix possible use of uninitialized
    field (bsc#1051510).

  - arm: OMAP2+: prm44xx: Fix section annotation on
    omap44xx_prm_enable_io_wakeup (bsc#1051510).

  - ASoC: dma-sh7760: cleanup a debug printk (bsc#1051510).

  - ASoC: rt5514-spi: Fix potential NULL pointer dereference
    (bsc#1051510).

  - ax25: fix a use-after-free in ax25_fillin_cb()
    (networking-stable-19_01_04).

  - be2net: do not flip hw_features when VXLANs are
    added/deleted (bsc#1050252).

  - blkdev: avoid migration stalls for blkdev pages
    (bsc#1084216).

  - blk-mq: fix kernel oops in blk_mq_tag_idle()
    (bsc#1051510).

  - block: break discard submissions into the user defined
    size (git-fixes).

  - block: cleanup __blkdev_issue_discard() (git-fixes).

  - block: do not deal with discard limit in
    blkdev_issue_discard() (git-fixes).

  - block: fix 32 bit overflow in __blkdev_issue_discard()
    (git-fixes).

  - block: fix infinite loop if the device loses discard
    capability (git-fixes).

  - block: make sure discard bio is aligned with logical
    block size (git-fixes).

  - block: make sure writesame bio is aligned with logical
    block size (git-fixes).

  - block/swim3: Fix -EBUSY error when re-opening device
    after unmount (git-fixes).

  - bnx2x: Assign unique DMAE channel number for FW DMAE
    transactions (bsc#1086323).

  - bnx2x: Clear fip MAC when fcoe offload support is
    disabled (bsc#1086323).

  - bnx2x: Fix NULL pointer dereference in
    bnx2x_del_all_vlans() on some hw (bsc#1086323).

  - bnx2x: Remove configured vlans as part of unload
    sequence (bsc#1086323).

  - bnx2x: Send update-svid ramrod with retry/poll flags
    enabled (bsc#1086323).

  - bonding: update nest level on unlink (git-fixes).

  - bsg: allocate sense buffer if requested (bsc#1106811).

  - btrfs: qgroup: Fix root item corruption when multiple
    same source snapshots are created with quota enabled
    (bsc#1122324).

  - can: bcm: check timer values before ktime conversion
    (bsc#1051510).

  - can: dev: __can_get_echo_skb(): fix bogous check for
    non-existing skb by removing it (bsc#1051510).

  - can: gw: ensure DLC boundaries after CAN frame
    modification (bsc#1051510).

  - cdc-acm: fix abnormal DATA RX issue for Mediatek
    Preloader (bsc#1051510).

  - char/mwave: fix potential Spectre v1 vulnerability
    (bsc#1051510).

  - checkstack.pl: fix for aarch64 (bsc#1051510).

  - cifs: add missing debug entries for kconfig options
    (bsc#1051510).

  - cifs: add missing support for ACLs in SMB 3.11
    (bsc#1051510).

  - cifs: add sha512 secmech (bsc#1051510).

  - cifs: Add support for reading attributes on SMB2+
    (bsc#1051510).

  - cifs: Add support for writing attributes on SMB2+
    (bsc#1051510).

  - cifs: do not log STATUS_NOT_FOUND errors for DFS
    (bsc#1051510).

  - cifs: Do not modify mid entry after submitting I/O in
    cifs_call_async (bsc#1051510).

  - cifs: Fix error mapping for SMB2_LOCK command which
    caused OFD lock problem (bsc#1051510).

  - cifs: Fix memory leak in smb2_set_ea() (bsc#1051510).

  - cifs: fix return value for cifs_listxattr (bsc#1051510).

  - cifs: Fix separator when building path from dentry
    (bsc#1051510).

  - cifs: fix set info (bsc#1051510).

  - cifs: fix sha512 check in cifs_crypto_secmech_release
    (bsc#1051510).

  - cifs: fix wrapping bugs in num_entries() (bsc#1051510).

  - cifs: For SMB2 security informaion query, check for
    minimum sized security descriptor instead of sizeof
    FileAllInformation class (bsc#1051510).

  - cifs: hide unused functions (bsc#1051510).

  - cifs: hide unused functions (bsc#1051510).

  - cifs: implement v3.11 preauth integrity (bsc#1051510).

  - cifs: make 'nodfs' mount opt a superblock flag
    (bsc#1051510).

  - cifs: prevent integer overflow in nxt_dir_entry()
    (bsc#1051510).

  - cifs: prototype declaration and definition for smb 2 - 3
    and cifsacl mount options (bsc#1051510).

  - cifs: prototype declaration and definition to set acl
    for smb 2 - 3 and cifsacl mount options (bsc#1051510).

  - cifs: refactor crypto shash/sdesc allocation&free
    (bsc#1051510).

  - cifs: smb2ops: Fix listxattr() when there are no EAs
    (bsc#1051510).

  - cifs: Use smb 2 - 3 and cifsacl mount options getacl
    functions (bsc#1051510).

  - cifs: Use smb 2 - 3 and cifsacl mount options setacl
    function (bsc#1051510).

  - cifs: Use ULL suffix for 64-bit constant (bsc#1051510).

  - clk: imx6q: reset exclusive gates on init (bsc#1051510).

  - clk: rockchip: fix typo in rk3188 spdif_frac parent
    (bsc#1051510).

  - clk: sunxi-ng: enable so-said LDOs for A64 SoC's
    pll-mipi clock (bsc#1051510).

  - clk: sunxi-ng: h3/h5: Fix CSI_MCLK parent (bsc#1051510).

  - cpufreq: imx6q: add return value check for voltage scale
    (bsc#1051510).

  - Cramfs: fix abad comparison when wrap-arounds occur
    (bsc#1051510).

  - crypto: authencesn - Avoid twice completion call in
    decrypt path (bsc#1051510).

  - crypto: authenc - fix parsing key with misaligned
    rta_len (bsc#1051510).

  - crypto: bcm - convert to use
    crypto_authenc_extractkeys() (bsc#1051510).

  - crypto: caam - fix zero-length buffer DMA mapping
    (bsc#1051510).

  - crypto: user - support incremental algorithm dumps
    (bsc#1120902).

  - dlm: fixed memory leaks after failed ls_remove_names
    allocation (bsc#1051510).

  - dlm: lost put_lkb on error path in receive_convert() and
    receive_unlock() (bsc#1051510).

  - dlm: memory leaks on error path in dlm_user_request()
    (bsc#1051510).

  - dlm: possible memory leak on error path in create_lkb()
    (bsc#1051510).

  - dmaengine: at_hdmac: fix memory leak in at_dma_xlate()
    (bsc#1051510).

  - dmaengine: at_hdmac: fix module unloading (bsc#1051510).

  - dmaengine: dma-jz4780: Return error if not probed from
    DT (bsc#1051510).

  - dmaengine: dw: Fix FIFO size for Intel Merrifield
    (bsc#1051510).

  - dmaengine: xilinx_dma: Remove __aligned attribute on
    zynqmp_dma_desc_ll (bsc#1051510).

  - dm cache metadata: verify cache has blocks in
    blocks_are_clean_separate_dirty() (git-fixes).

  - dm: call blk_queue_split() to impose device limits on
    bios (git-fixes).

  - dm: do not allow readahead to limit IO size (git-fixes).

  - dm thin: send event about thin-pool state change _after_
    making it (git-fixes).

  - dm zoned: Fix target BIO completion handling
    (git-fixes).

  - Do not log expected error on DFS referral request
    (bsc#1051510).

  - driver core: Move async_synchronize_full call
    (bsc#1051510).

  - drivers: core: Remove glue dirs from sysfs earlier
    (bsc#1051510).

  - drivers/misc/sgi-gru: fix Spectre v1 vulnerability
    (bsc#1051510).

  - drivers/net/ethernet/qlogic/qed/qed_rdma.h: fix typo
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - drivers/sbus/char: add of_node_put() (bsc#1051510).

  - drivers/tty: add missing of_node_put() (bsc#1051510).

  - drm/fb-helper: Ignore the value of
    fb_var_screeninfo.pixclock (bsc#1113722)

  - drm/fb-helper: Partially bring back workaround for bugs
    of SDL 1.2 (bsc#1113722)

  - drm/i915/gvt: Fix mmap range check (bsc#1120902)

  - drm/nouveau/tmr: detect stalled gpu timer and break out
    of waits (bsc#1123538).

  - drm/vmwgfx: Fix setting of dma masks (bsc#1120902)

  - drm/vmwgfx: Return error code from
    vmw_execbuf_copy_fence_user (bsc#1120902)

  - e1000e: allow non-monotonic SYSTIM readings
    (bsc#1051510).

  - exportfs: do not read dentry after free (bsc#1051510).

  - ext4: Fix crash during online resizing (bsc#1122779).

  - fanotify: fix handling of events on child sub-directory
    (bsc#1122019).

  - fat: validate ->i_start before using (bsc#1051510).

  - fix smb3-encryption breakage when CONFIG_DEBUG_SG=y
    (bsc#1051510).

  - fork: do not copy inconsistent signal handler state to
    child (bsc#1051510).

  - fork: record start_time late (git-fixes).

  - fork: unconditionally clear stack on fork (git-fixes).

  - fs/cifs: require sha512 (bsc#1051510).

  - gpio: altera-a10sr: Set proper output level for
    direction_output (bsc#1051510).

  - gpio: pcf857x: Fix interrupts on multiple instances
    (bsc#1051510).

  - gpio: pl061: handle failed allocations (bsc#1051510).

  - gpio: pl061: Move irq_chip definition inside struct
    pl061 (bsc#1051510).

  - gpio: vf610: Mask all GPIO interrupts (bsc#1051510).

  - gro_cell: add napi_disable in gro_cells_destroy
    (networking-stable-19_01_04).

  - hfs: do not free node before using (bsc#1051510).

  - hfsplus: do not free node before using (bsc#1051510).

  - hfsplus: prevent btree data loss on root split
    (bsc#1051510).

  - hfs: prevent btree data loss on root split
    (bsc#1051510).

  - i2c: dev: prevent adapter retries and timeout being set
    as minus value (bsc#1051510).

  - i40e: fix mac filter delete when setting mac address
    (bsc#1056658 bsc#1056662).

  - i40e: report correct statistics when XDP is enabled
    (bsc#1056658 bsc#1056662).

  - i40e: restore NETIF_F_GSO_IPXIP to netdev features
    (bsc#1056658 bsc#1056662).

  - ibmveth: Do not process frames after calling
    napi_reschedule (bcs#1123357).

  - ibmveth: fix DMA unmap error in ibmveth_xmit_start error
    path (networking-stable-19_01_04).

  - ibmvnic: Add ethtool private flag for driver-defined
    queue limits (bsc#1121726).

  - ibmvnic: Increase maximum queue size limit
    (bsc#1121726).

  - ibmvnic: Introduce driver limits for ring sizes
    (bsc#1121726).

  - ide: pmac: add of_node_put() (bsc#1051510).

  - ieee802154: lowpan_header_create check must check daddr
    (networking-stable-19_01_04).

  - input: elan_i2c - add ACPI ID for touchpad in ASUS
    Aspire F5-573G (bsc#1051510).

  - input: omap-keypad - fix idle configuration to not block
    SoC idle states (bsc#1051510).

  - input: raspberrypi-ts - fix link error (git-fixes).

  - input: restore EV_ABS ABS_RESERVED (bsc#1051510).

  - input: synaptics - enable RMI on ThinkPad T560
    (bsc#1051510).

  - input: synaptics - enable SMBus for HP EliteBook 840 G4
    (bsc#1051510).

  - input: xpad - add support for SteelSeries Stratus Duo
    (bsc#1111666).

  - iommu/amd: Call free_iova_fast with pfn in map_sg
    (bsc#1106105).

  - iommu/amd: Fix IOMMU page flush when detach device from
    a domain (bsc#1106105).

  - iommu/amd: Unmap all mapped pages in error path of
    map_sg (bsc#1106105).

  - iommu/vt-d: Fix memory leak in
    intel_iommu_put_resv_regions() (bsc#1106105).

  - ip6mr: Fix potential Spectre v1 vulnerability
    (networking-stable-19_01_04).

  - ipmi:pci: Blacklist a Realtek 'IPMI' device (git-fixes).

  - ipmi:ssif: Fix handling of multi-part return messages
    (bsc#1051510).

  - ip: on queued skb use skb_header_pointer instead of
    pskb_may_pull (git-fixes).

  - ipv4: Fix potential Spectre v1 vulnerability
    (networking-stable-19_01_04).

  - ipv4: ipv6: netfilter: Adjust the frag mem limit when
    truesize changes (networking-stable-18_12_12).

  - ipv6: Check available headroom in ip6_xmit() even
    without options (networking-stable-18_12_12).

  - ipv6: explicitly initialize udp6_addr in
    udp_sock_create6() (networking-stable-19_01_04).

  - ipv6: sr: properly initialize flowi6 prior passing to
    ip6_route_output (networking-stable-18_12_12).

  - ipv6: tunnels: fix two use-after-free
    (networking-stable-19_01_04).

  - ip: validate header length on virtual device xmit
    (networking-stable-19_01_04).

  - iscsi target: fix session creation failure handling
    (bsc#1051510).

  - isdn: fix kernel-infoleak in capi_unlocked_ioctl
    (bsc#1051510).

  - iwlwifi: fix non_shared_ant for 22000 devices
    (bsc#1119086).

  - iwlwifi: fix wrong WGDS_WIFI_DATA_SIZE (bsc#1119086).

  - iwlwifi: mvm: do not send GEO_TX_POWER_LIMIT to old
    firmwares (bsc#1119086).

  - jffs2: Fix use of uninitialized delayed_work, lockdep
    breakage (bsc#1051510).

  - kABI: fix xhci kABI stability (bsc#1119086).

  - kABI: protect struct sctp_association (kabi).

  - kABI workaround for deleted
    snd_hda_register_beep_device() (bsc#1122944).

  - kABI workaround for snd_hda_bus.bus_probing addition
    (bsc#1122944).

  - kdb: use memmove instead of overlapping memcpy
    (bsc#1120954).

  - kernel/exit.c: release ptraced tasks before
    zap_pid_ns_processes (git-fixes).

  - kvm: arm/arm64: Properly protect VGIC locks from IRQs
    (bsc#1117155).

  - kvm: arm/arm64: VGIC/ITS: Promote irq_lock() in
    update_affinity (bsc#1117155).

  - kvm: arm/arm64: VGIC/ITS: protect kvm_read_guest() calls
    with SRCU lock (bsc#1117155).

  - kvm: arm/arm64: VGIC/ITS save/restore: protect
    kvm_read_guest() calls (bsc#1117155).

  - kvm: PPC: Book3S PR: Set hflag to indicate that POWER9
    supports 1T segments (bsc#1124589).

  - kvm: sev: Fail KVM_SEV_INIT if already initialized
    (bsc#1114279).

  - kvm: x86: fix L1TF's MMIO GFN calculation (bsc#1124204).

  - lan78xx: Resolve issue with changing MAC address
    (bsc#1051510).

  - libertas_tf: prevent underflow in process_cmdrequest()
    (bsc#1119086).

  - lib/rbtree-test: lower default params (git-fixes).

  - lockd: fix access beyond unterminated strings in prints
    (git-fixes).

  - LSM: Check for NULL cred-security on free (bsc#1051510).

  - md: fix raid10 hang issue caused by barrier (git-fixes).

  - media: firewire: Fix app_info parameter type in
    avc_ca{,_app}_info (bsc#1051510).

  - media: usb: pwc: Do not use coherent DMA buffers for ISO
    transfer (bsc#1054610).

  - media: v4l2-tpg: array index could become negative
    (bsc#1051510).

  - media: v4l: ioctl: Validate num_planes for debug
    messages (bsc#1051510).

  - media: vb2: be sure to unlock mutex on errors
    (bsc#1051510).

  - media: vb2: vb2_mmap: move lock up (bsc#1051510).

  - media: vivid: fix error handling of kthread_run
    (bsc#1051510).

  - media: vivid: free bitmap_cap when updating
    std/timings/etc (bsc#1051510).

  - media: vivid: set min width/height to a value > 0
    (bsc#1051510).

  - mfd: ab8500-core: Return zero in
    get_register_interruptible() (bsc#1051510).

  - mfd: tps6586x: Handle interrupts on suspend
    (bsc#1051510).

  - misc: atmel-ssc: Fix section annotation on
    atmel_ssc_get_driver_data (bsc#1051510).

  - misc: hmc6352: fix potential Spectre v1 (bsc#1051510).

  - misc: mic/scif: fix copy-paste error in
    scif_create_remote_lookup (bsc#1051510).

  - misc: mic: SCIF Fix scif_get_new_port() error handling
    (bsc#1051510).

  - misc: sram: enable clock before registering regions
    (bsc#1051510).

  - misc: sram: fix resource leaks in probe error path
    (bsc#1051510).

  - misc: ti-st: Fix memory leak in the error path of
    probe() (bsc#1051510).

  - misc: vexpress: Off by one in vexpress_syscfg_exec()
    (bsc#1051510).

  - mmc: atmel-mci: do not assume idle after
    atmci_request_end (bsc#1051510).

  - mmc: bcm2835: Fix DMA channel leak on probe error
    (bsc#1051510).

  - mmc: dw_mmc-bluefield: : Fix the license information
    (bsc#1051510).

  - mmc: sdhci-iproc: handle mmc_of_parse() errors during
    probe (bsc#1051510).

  - mm/huge_memory: fix lockdep complaint on 32-bit
    i_size_read() (VM Functionality, bsc#1121599).

  - mm/huge_memory: rename freeze_page() to unmap_page() (VM
    Functionality, bsc#1121599).

  - mm/huge_memory: splitting set mapping+index before
    unfreeze (VM Functionality, bsc#1121599).

  - mm/khugepaged: collapse_shmem() do not crash on Compound
    (VM Functionality, bsc#1121599).

  - mm/khugepaged: collapse_shmem() remember to clear holes
    (VM Functionality, bsc#1121599).

  - mm/khugepaged: collapse_shmem() stop if punched or
    truncated (VM Functionality, bsc#1121599).

  - mm/khugepaged: collapse_shmem() without freezing
    new_page (VM Functionality, bsc#1121599).

  - mm/khugepaged: fix crashes due to misaccounted holes (VM
    Functionality, bsc#1121599).

  - mm/khugepaged: minor reorderings in collapse_shmem() (VM
    Functionality, bsc#1121599).

  - mm: migrate: lock buffers before
    migrate_page_move_mapping() (bsc#1084216).

  - mm: migrate: Make buffer_migrate_page_norefs() actually
    succeed (bsc#1084216)

  - mm: migrate: provide buffer_migrate_page_norefs()
    (bsc#1084216).

  - mm: migration: factor out code to compute expected
    number of page references (bsc#1084216).

  - Move the upstreamed HD-audio fix into sorted section

  - mpt3sas: check sense buffer before copying sense data
    (bsc#1106811).

  - neighbour: Avoid writing before skb->head in
    neigh_hh_output() (networking-stable-18_12_12).

  - net: 8139cp: fix a BUG triggered by changing mtu with
    network traffic (networking-stable-18_12_12).

  - net: core: Fix Spectre v1 vulnerability
    (networking-stable-19_01_04).

  - net/hamradio/6pack: use mod_timer() to rearm timers
    (networking-stable-19_01_04).

  - net: hns3: add error handler for
    hns3_nic_init_vector_data() (bsc#1104353).

  - net: hns3: add handling for big TX fragment (bsc#1104353
    ).

  - net: hns3: Fix client initialize state issue when roce
    client initialize failed (bsc#1104353).

  - net: hns3: Fix for loopback selftest failed problem
    (bsc#1104353 ).

  - net: hns3: fix for multiple unmapping DMA problem
    (bsc#1104353 ).

  - net: hns3: Fix tc setup when netdev is first up
    (bsc#1104353 ).

  - net: hns3: Fix tqp array traversal condition for vf
    (bsc#1104353 ).

  - net: hns3: move DMA map into hns3_fill_desc (bsc#1104353
    ).

  - net: hns3: remove hns3_fill_desc_tso (bsc#1104353).

  - net: hns3: rename hns_nic_dma_unmap (bsc#1104353).

  - net: hns3: rename the interface for init_client_instance
    and uninit_client_instance (bsc#1104353).

  - net: macb: restart tx after tx used bit read
    (networking-stable-19_01_04).

  - net/mlx4_en: Change min MTU size to ETH_MIN_MTU
    (networking-stable-18_12_12).

  - net/mlx5e: Remove the false indication of software
    timestamping support (networking-stable-19_01_04).

  - net/mlx5: Typo fix in del_sw_hw_rule
    (networking-stable-19_01_04).

  - net: phy: do not allow __set_phy_supported to add
    unsupported modes (networking-stable-18_12_12).

  - net: phy: Fix the issue that netif always links up after
    resuming (networking-stable-19_01_04).

  - netrom: fix locking in nr_find_socket()
    (networking-stable-19_01_04).

  - net: skb_scrub_packet(): Scrub offload_fwd_mark
    (networking-stable-18_12_03).

  - net/smc: fix TCP fallback socket release
    (networking-stable-19_01_04).

  - net: stmmac: Fix PCI module removal leak (git-fixes).

  - net: thunderx: set tso_hdrs pointer to NULL in
    nicvf_free_snd_queue (networking-stable-18_12_03).

  - net: thunderx: set xdp_prog to NULL if bpf_prog_add
    fails (networking-stable-18_12_03).

  - net/wan: fix a double free in x25_asy_open_tty()
    (networking-stable-19_01_04).

  - nfsd: COPY and CLONE operations require the saved
    filehandle to be set (git-fixes).

  - nfsd: Fix an Oops in free_session() (git-fixes).

  - nfs: Fix a missed page unlock after pg_doio()
    (git-fixes).

  - NFS: Fix up return value on fatal errors in
    nfs_page_async_flush() (git-fixes).

  - NFSv4.1: Fix the r/wsize checking (git-fixes).

  - NFSv4: Do not exit the state manager without clearing
    NFS4CLNT_MANAGER_RUNNING (git-fixes).

  - nvme-multipath: round-robin I/O policy (bsc#1110705).

  - omap2fb: Fix stack memory disclosure (bsc#1120902)

  - packet: Do not leak dev refcounts on error exit
    (git-fixes).

  - packet: validate address length if non-zero
    (networking-stable-19_01_04).

  - packet: validate address length
    (networking-stable-19_01_04).

  - PCI: Disable broken RTIT_BAR of Intel TH (bsc#1120318).

  - phonet: af_phonet: Fix Spectre v1 vulnerability
    (networking-stable-19_01_04).

  - platform/x86: asus-nb-wmi: Drop mapping of 0x33 and 0x34
    scan codes (bsc#1051510).

  - platform/x86: asus-nb-wmi: Map 0x35 to KEY_SCREENLOCK
    (bsc#1051510).

  - platform/x86: asus-wmi: Tell the EC the OS will handle
    the display off hotkey (bsc#1051510).

  - powerpc: Always save/restore checkpointed regs during
    treclaim/trecheckpoint (bsc#1118338).

  - powerpc/cacheinfo: Report the correct shared_cpu_map on
    big-cores (bsc#1109695).

  - powerpc: Detect the presence of big-cores via 'ibm,
    thread-groups' (bsc#1109695).

  - powerpc: make use of for_each_node_by_type() instead of
    open-coding it (bsc#1109695).

  - powerpc/powernv: Clear LPCR[PECE1] via stop-api only for
    deep state offline (bsc#1119766, bsc#1055121).

  - powerpc/powernv: Clear PECE1 in LPCR via stop-api only
    on Hotplug (bsc#1119766, bsc#1055121).

  - powerpc: Remove facility loadups on transactional {fp,
    vec, vsx} unavailable (bsc#1118338).

  - powerpc: Remove redundant FP/Altivec giveup code
    (bsc#1118338).

  - powerpc/setup: Add cpu_to_phys_id array (bsc#1109695).

  - powerpc/smp: Add cpu_l2_cache_map (bsc#1109695).

  - powerpc/smp: Add Power9 scheduler topology
    (bsc#1109695).

  - powerpc/smp: Rework CPU topology construction
    (bsc#1109695).

  - powerpc/smp: Use cpu_to_chip_id() to find core siblings
    (bsc#1109695).

  - powerpc/tm: Avoid machine crash on rt_sigreturn
    (bsc#1118338).

  - powerpc/tm: Do not check for WARN in TM Bad Thing
    handling (bsc#1118338).

  - powerpc/tm: Fix comment (bsc#1118338).

  - powerpc/tm: Fix endianness flip on trap (bsc#1118338).

  - powerpc/tm: Fix HFSCR bit for no suspend case
    (bsc#1118338).

  - powerpc/tm: Fix HTM documentation (bsc#1118338).

  - powerpc/tm: Limit TM code inside PPC_TRANSACTIONAL_MEM
    (bsc#1118338).

  - powerpc/tm: P9 disable transactionally suspended
    sigcontexts (bsc#1118338).

  - powerpc/tm: Print 64-bits MSR (bsc#1118338).

  - powerpc/tm: Print scratch value (bsc#1118338).

  - powerpc/tm: Reformat comments (bsc#1118338).

  - powerpc/tm: Remove msr_tm_active() (bsc#1118338).

  - powerpc/tm: Remove struct thread_info param from
    tm_reclaim_thread() (bsc#1118338).

  - powerpc/tm: Save MSR to PACA before RFID (bsc#1118338).

  - powerpc/tm: Set MSR[TS] just prior to recheckpoint
    (bsc#1118338, bsc#1120955).

  - powerpc/tm: Unset MSR[TS] if not recheckpointing
    (bsc#1118338).

  - powerpc/tm: Update function prototype comment
    (bsc#1118338).

  - powerpc: Use cpu_smallcore_sibling_mask at SMT level on
    bigcores (bsc#1109695).

  - powerpc/xmon: Fix invocation inside lock region
    (bsc#1122885).

  - pstore/ram: Avoid allocation and leak of platform data
    (bsc#1051510).

  - pstore/ram: Avoid NULL deref in ftrace merging failure
    path (bsc#1051510).

  - pstore/ram: Correctly calculate usable PRZ bytes
    (bsc#1051510).

  - pstore/ram: Do not treat empty buffers as valid
    (bsc#1051510).

  - ptp_kvm: probe for kvm guest availability (bsc#1098382).

  - ptr_ring: wrap back ->producer in
    __ptr_ring_swap_queue() (networking-stable-19_01_04).

  - qed: Avoid constant logical operation warning in
    qed_vf_pf_acquire (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Avoid implicit enum conversion in
    qed_iwarp_parse_rx_pkt (bsc#1086314 bsc#1086313
    bsc#1086301 ).

  - qed: Avoid implicit enum conversion in
    qed_roce_mode_to_flavor (bsc#1086314 bsc#1086313
    bsc#1086301 ).

  - qed: Avoid implicit enum conversion in
    qed_set_tunn_cls_info (bsc#1086314 bsc#1086313
    bsc#1086301 ).

  - qed: Fix an error code qed_ll2_start_xmit() (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Fix bitmap_weight() check (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qed: Fix blocking/unlimited SPQ entries leak
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix command number mismatch between driver and the
    mfw (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: Fix mask parameter in qed_vf_prep_tunn_req_tlv
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix memory/entry leak in qed_init_sp_request()
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix potential memory corruption (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Fix PTT leak in qed_drain() (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Fix QM getters to always return a valid pq
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix rdma_info structure allocation (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Fix reading wrong value in loop condition
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qla2xxx: Fixup dual-protocol FCP connections
    (bsc#1108870).

  - qmi_wwan: Added support for Fibocom NL668 series
    (networking-stable-19_01_04).

  - qmi_wwan: Added support for Telit LN940 series
    (networking-stable-19_01_04).

  - qmi_wwan: Add support for Fibocom NL678 series
    (networking-stable-19_01_04).

  - rapidio/rionet: do not free skb before reading its
    length (networking-stable-18_12_03).

  - RDMA/core: Fix unwinding flow in case of error to
    register device (bsc#1046306).

  - Revert 'serial: 8250: Fix clearing FIFOs in RS485 mode
    again' (bsc#1051510).

  - rpm/release-projects: Add SUSE:Maintenance:* for MU
    kernels (bsc#1123317)

  - rtnetlink: ndo_dflt_fdb_dump() only work for
    ARPHRD_ETHER devices (networking-stable-18_12_12).

  - s390/zcrypt: fix specification exception on z196 during
    ap probe (LTC#174936, bsc#1123061).

  - sbus: char: add of_node_put() (bsc#1051510).

  - sched/wait: Fix rcuwait_wake_up() ordering (git-fixes).

  - scripts/git_sort/git_sort.py: Add mkp/scsi
    5.0/scsi-fixes

  - scripts/git_sort/git_sort.py: Add s390/linux.git fixes.

  - scsi: qedi: Add ep_state for login completion on
    un-reachable targets (bsc#1113712).

  - scsi: qla2xxx: Timeouts occur on surprise removal of
    QLogic adapter (bsc#1124985).

  - scsi: target: make the pi_prot_format ConfigFS path
    readable (bsc#1123933).

  - sctp: initialize sin6_flowinfo for ipv6 addrs in
    sctp_inet6addr_event (networking-stable-19_01_04).

  - sctp: kfree_rcu asoc (networking-stable-18_12_12).

  - selftests/powerpc: Use snprintf to construct DSCR sysfs
    interface paths (bsc#1124579).

  - selinux: Add __GFP_NOWARN to allocation at str_read()
    (bsc#1051510).

  - selinux: fix GPF on invalid policy (bsc#1051510).

  - serial: imx: fix error handling in console_setup
    (bsc#1051510).

  - serial: set suppress_bind_attrs flag only if builtin
    (bsc#1051510).

  - serial/sunsu: fix refcount leak (bsc#1051510).

  - serial: uartps: Fix interrupt mask issue to handle the
    RX interrupts properly (bsc#1051510).

  - shmem: introduce shmem_inode_acct_block (VM
    Functionality, bsc#1121599).

  - shmem: shmem_charge: verify max_block is not exceeded
    before inode update (VM Functionality, bsc#1121599).

  - signal: Always deliver the kernel's SIGKILL and SIGSTOP
    to a pid namespace init (git-fixes).

  - slab: alien caches must not be initialized if the
    allocation of the alien cache failed (git fixes
    (mm/slab)).

  - smb3.1.1 dialect is no longer experimental
    (bsc#1051510).

  - smb311: Fix reconnect (bsc#1051510).

  - smb3: Add support for multidialect negotiate (SMB2.1 and
    later) (bsc#1051510).

  - smb3: allow stats which track session and share
    reconnects to be reset (bsc#1051510).

  - smb3: Backup intent flag missing for directory opens
    with backupuid mounts (bsc#1051510).

  - smb3: check for and properly advertise directory lease
    support (bsc#1051510).

  - smb3: directory sync should not return an error
    (bsc#1051510).

  - smb3: do not attempt cifs operation in smb3 query info
    error path (bsc#1051510).

  - smb3: do not request leases in symlink creation and
    query (bsc#1051510).

  - smb3: Do not send SMB3 SET_INFO if nothing changed
    (bsc#1051510).

  - smb3: enumerating snapshots was leaving part of the data
    off end (bsc#1051510).

  - smb3: Fix length checking of SMB3.11 negotiate request
    (bsc#1051510).

  - smb3: Fix root directory when server returns inode
    number of zero (bsc#1051510).

  - smb3: fix various xid leaks (bsc#1051510).

  - smb3: Improve security, move default dialect to SMB3
    from old CIFS (bsc#1051510).

  - smb3: on kerberos mount if server does not specify auth
    type use krb5 (bsc#1051510).

  - smb3: Remove ifdef since SMB3 (and later) now STRONGLY
    preferred (bsc#1051510).

  - smb3: simplify code by removing CONFIG_CIFS_SMB311
    (bsc#1051510).

  - staging: rtl8188eu: Add device code for D-Link DWA-121
    rev B1 (bsc#1051510).

  - sunrpc: correct the computation for page_ptr when
    truncating (git-fixes).

  - sunrpc: Fix a potential race in xprt_connect()
    (git-fixes).

  - sunrpc: Fix leak of krb5p encode pages (git-fixes).

  - sunrpc: handle ENOMEM in rpcb_getport_async (git-fixes).

  - sunrpc: safely reallow resvport min/max inversion
    (git-fixes).

  - tcp: Do not underestimate rwnd_limited
    (networking-stable-18_12_12).

  - tcp: fix a race in inet_diag_dump_icsk()
    (networking-stable-19_01_04).

  - tcp: fix NULL ref in tail loss probe
    (networking-stable-18_12_12).

  - tcp: lack of available data can also cause TSO defer
    (git-fixes).

  - thermal: int340x_thermal: Fix a NULL vs IS_ERR() check
    (bsc#1051510).

  - tipc: compare remote and local protocols in
    tipc_udp_enable() (networking-stable-19_01_04).

  - tipc: fix a double kfree_skb()
    (networking-stable-19_01_04).

  - tipc: use lock_sock() in tipc_sk_reinit()
    (networking-stable-19_01_04).

  - tools/lib/lockdep: Rename 'trywlock' into 'trywrlock'
    (bsc#1121973).

  - tty: Do not hold ldisc lock in tty_reopen() if ldisc
    present (bsc#1051510).

  - tty: Handle problem if line discipline does not have
    receive_buf (bsc#1051510).

  - tty/n_hdlc: fix __might_sleep warning (bsc#1051510).

  - tty/serial: do not free trasnmit buffer page under port
    lock (bsc#1051510).

  - tun: forbid iface creation with rtnl ops
    (networking-stable-18_12_12).

  - uart: Fix crash in uart_write and uart_put_char
    (bsc#1051510).

  - usb: Add USB_QUIRK_DELAY_CTRL_MSG quirk for Corsair K70
    RGB (bsc#1120902).

  - usb: cdc-acm: send ZLP for Telit 3G Intel based modems
    (bsc#1120902).

  - usb: dwc3: gadget: Clear req->needs_extra_trb flag on
    cleanup (bsc#1120902).

  - usb: dwc3: trace: add missing break statement to make
    compiler happy (bsc#1120902).

  - usbnet: ipheth: fix potential recvmsg bug and recvmsg
    bug 2 (networking-stable-18_12_03).

  - usb: serial: option: add Fibocom NL678 series
    (bsc#1120902).

  - usb: serial: pl2303: add ids for Hewlett-Packard HP POS
    pole displays (bsc#1120902).

  - usb: storage: add quirk for SMI SM3350 (bsc#1120902).

  - usb: storage: do not insert sane sense for SPC3+ when
    bad sense specified (bsc#1120902).

  - usb: xhci: fix 'broken_suspend' placement in struct
    xchi_hcd (bsc#1119086).

  - vfs: Avoid softlockups in drop_pagecache_sb()
    (bsc#1118505).

  - vhost: make sure used idx is seen before log in
    vhost_add_used_n() (networking-stable-19_01_04).

  - virtio-net: fail XDP set if guest csum is negotiated
    (networking-stable-18_12_03).

  - virtio-net: keep vnet header zeroed after processing XDP
    (networking-stable-18_12_12).

  - vsock: Send reset control packet when socket is
    partially bound (networking-stable-19_01_04).

  - vt: invoke notifier on screen size change (bsc#1051510).

  - watchdog: w83627hf_wdt: Add quirk for Inves system
    (bsc#1106434).

  - writeback: do not decrement wb->refcnt if !wb->bdi (git
    fixes (writeback)).

  - x86/bugs: Add AMD's variant of SSB_NO (bsc#1114279).

  - x86/bugs: Update when to check for the LS_CFG SSBD
    mitigation (bsc#1114279).

  - x86/kvmclock: set pvti_cpu0_va after enabling kvmclock
    (bsc#1098382).

  - x86/MCE: Initialize mce.bank in the case of a fatal
    error in mce_no_way_out() (bsc#1114279).

  - x86/microcode/amd: Do not falsely trick the late loading
    mechanism (bsc#1114279).

  - x86/mm: Drop usage of __flush_tlb_all() in
    kernel_physical_mapping_init() (bsc#1114279).

  - x86, modpost: Replace last remnants of RETPOLINE with
    CONFIG_RETPOLINE (bsc#1114279).

  - x86/pvclock: add setter for pvclock_pvti_cpu0_va
    (bsc#1098382).

  - x86/resctrl: Fix rdt_find_domain() return value and
    checks (bsc#1114279).

  - x86/speculation: Add RETPOLINE_AMD support to the inline
    asm CALL_NOSPEC variant (bsc#1114279).

  - x86/speculation: Remove redundant arch_smt_update()
    invocation (bsc#1114279).

  - x86/xen/time: Output xen sched_clock time from 0
    (bsc#1098382).

  - x86/xen/time: set pvclock flags on xen_time_init()
    (bsc#1098382).

  - x86/xen/time: setup vcpu 0 time info page (bsc#1098382).

  - xen: Fix x86 sched_clock() interface for xen
    (bsc#1098382).

  - xhci: Add quirk to zero 64bit registers on Renesas PCIe
    controllers (bsc#1120854).

  - xhci: workaround CSS timeout on AMD SNPS 3.0 xHC
    (bsc#1119086).

  - xprtrdma: Reset credit grant properly after a disconnect
    (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=802154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.48.1") ) flag++;

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
