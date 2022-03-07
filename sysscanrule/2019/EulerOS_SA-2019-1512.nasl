#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124834);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2016-10741",
    "CVE-2017-18360",
    "CVE-2017-7518",
    "CVE-2018-16862",
    "CVE-2018-17972",
    "CVE-2018-18281",
    "CVE-2018-18559",
    "CVE-2018-18710",
    "CVE-2018-19824",
    "CVE-2018-5332",
    "CVE-2018-5333",
    "CVE-2018-5344",
    "CVE-2018-5391",
    "CVE-2018-5750",
    "CVE-2018-6927",
    "CVE-2018-7757",
    "CVE-2018-8781",
    "CVE-2019-3701",
    "CVE-2019-5489",
    "CVE-2019-9213"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1512)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - In the Linux kernel through 4.14.13, the
    rds_message_alloc_sgs() function does not validate a
    value that is used during DMA page allocation, leading
    to a heap-based out-of-bounds write (related to the
    rds_rdma_extra_size() function in 'net/rds/rdma.c') and
    thus to a system panic. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-5332)

  - In the Linux kernel through 4.14.13, the
    rds_cmsg_atomic() function in 'net/rds/rdma.c'
    mishandles cases where page pinning fails or an invalid
    address is supplied by a user. This can lead to a NULL
    pointer dereference in rds_atomic_free_op() and thus to
    a system panic.(CVE-2018-5333)

  - A flaw was found in the Linux kernel's handling of
    loopback devices. An attacker, who has permissions to
    setup loopback disks, may create a denial of service or
    other unspecified actions.(CVE-2018-5344)

  - The acpi_smbus_hc_add function in drivers/acpi/sbshc.c
    in the Linux kernel, through 4.14.15, allows local
    users to obtain sensitive address information by
    reading dmesg data from an SBS HC printk
    call.(CVE-2018-5750)

  - The futex_requeue function in kernel/futex.c in the
    Linux kernel, before 4.14.15, might allow attackers to
    cause a denial of service (integer overflow) or
    possibly have unspecified other impacts by triggering a
    negative wake or requeue value. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled
    out, although we believe it is unlikely.(CVE-2018-6927)

  - Memory leak in the sas_smp_get_phy_events function in
    drivers/scsi/libsas/sas_expander.c in the Linux kernel
    allows local users to cause a denial of service (kernel
    memory exhaustion) via multiple read accesses to files
    in the /sys/class/sas_phy directory.(CVE-2018-7757)

  - A an integer overflow vulnerability was discovered in
    the Linux kernel, from version 3.4 through 4.15, in the
    drivers/gpu/drm/udl/udl_fb.c:udl_fb_mmap() function. An
    attacker with access to the udldrmfb driver could
    exploit this to obtain full read and write permissions
    on kernel physical pages, resulting in a code execution
    in kernel space.(CVE-2018-8781)

  - A flaw was found in the way the Linux KVM module
    processed the trap flag(TF) bit in EFLAGS during
    emulation of the syscall instruction, which leads to a
    debug exception(#DB) being raised in the guest stack. A
    user/process inside a guest could use this flaw to
    potentially escalate their privileges inside the guest.
    Linux guests are not affected by this.(CVE-2017-7518)

  - A division-by-zero in set_termios(), when debugging is
    enabled, was found in the Linux kernel. When the
    [io_ti] driver is loaded, a local unprivileged attacker
    can request incorrect high transfer speed in the
    change_port_settings() in the
    drivers/usb/serial/io_ti.c so that the divisor value
    becomes zero and causes a system crash resulting in a
    denial of service.(CVE-2017-18360)

  - It was found that the Linux kernel can hit a BUG_ON()
    statement in the __xfs_get_blocks() in the
    fs/xfs/xfs_aops.c because of a race condition between
    direct and memory-mapped I/O associated with a hole in
    a file that is handled with BUG_ON() instead of an I/O
    failure. This allows a local unprivileged attacker to
    cause a system crash and a denial of
    service.(CVE-2016-10741)

  - Since Linux kernel version 3.2, the mremap() syscall
    performs TLB flushes after dropping pagetable locks. If
    a syscall such as ftruncate() removes entries from the
    pagetables of a task that is in the middle of mremap(),
    a stale TLB entry can remain for a short time that
    permits access to a physical page after it has been
    released back to the page allocator and reused. This is
    fixed in the following kernel versions: 4.9.135,
    4.14.78, 4.18.16, 4.19.(CVE-2018-18281)

  - An issue was discovered in the proc_pid_stack function
    in fs/proc/base.c in the Linux kernel. An attacker with
    a local account can trick the stack unwinder code to
    leak stack contents to userspace. The fix allows only
    root to inspect the kernel stack of an arbitrary
    task.(CVE-2018-17972)

  - An issue was discovered in can_can_gw_rcv in
    net/can/gw.c in the Linux kernel through 4.19.13. The
    CAN frame modification rules allow bitwise logical
    operations that can be also applied to the can_dlc
    field. Because of a missing check, the CAN drivers may
    write arbitrary content beyond the data registers in
    the CAN controller's I/O memory when processing can-gw
    manipulated outgoing frames. This is related to
    cgw_csum_xor_rel. An unprivileged user can trigger a
    system crash (general protection fault).(CVE-2019-3701)

  - A flaw was found In the Linux kernel, through version
    4.19.6, where a local user could exploit a
    use-after-free in the ALSA driver by supplying a
    malicious USB Sound device (with zero interfaces) that
    is mishandled in usb_audio_probe in sound/usb/card.c.
    An attacker could corrupt memory and possibly escalate
    privileges if the attacker is able to have physical
    access to the system.(CVE-2018-19824)

  - A security flaw was found in the Linux kernel in a way
    that the cleancache subsystem clears an inode after the
    final file truncation (removal). The new file created
    with the same inode may contain leftover pages from
    cleancache and the old file data instead of the new
    one.(CVE-2018-16862)

  - A use-after-free flaw can occur in the Linux kernel due
    to a race condition between packet_do_bind() and
    packet_notifier() functions called for an AF_PACKET
    socket. An unprivileged, local user could use this flaw
    to induce kernel memory corruption on the system,
    leading to an unresponsive system or to a crash. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out.(CVE-2018-18559)

  - A new software page cache side channel attack scenario
    was discovered in operating systems that implement the
    very common 'page cache' caching mechanism. A malicious
    user/process could use 'in memory' page-cache knowledge
    to infer access timings to shared memory and gain
    knowledge which can be used to reduce effectiveness of
    cryptographic strength by monitoring algorithmic
    behavior, infer access patterns of memory to determine
    code paths taken, and exfiltrate data to a blinded
    attacker through page-granularity access times as a
    side-channel.(CVE-2019-5489)

  - A flaw was found in mmap in the Linux kernel allowing
    the process to map a null page. This allows attackers
    to abuse this mechanism to turn null pointer
    dereferences into workable exploits.(CVE-2019-9213)

  - A flaw named FragmentSmack was found in the way the
    Linux kernel handled reassembly of fragmented IPv4 and
    IPv6 packets. A remote attacker could use this flaw to
    trigger time and calculation expensive fragment
    reassembly algorithm by sending specially crafted
    packets which could lead to a CPU saturation and hence
    a denial of service on the system.(CVE-2018-5391)

  - An issue was discovered in the Linux kernel through
    4.19. An information leak in cdrom_ioctl_select_disc in
    drivers/cdrom/cdrom.c could be used by local attackers
    to read kernel memory because a cast from unsigned long
    to int interferes with bounds checking.(CVE-2018-18710)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1512
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
