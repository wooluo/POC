#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122699);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:24");

  script_cve_id(
    "CVE-2017-18360",
    "CVE-2018-10322",
    "CVE-2018-1092",
    "CVE-2018-1094",
    "CVE-2018-13094",
    "CVE-2018-14641",
    "CVE-2018-18281",
    "CVE-2018-18397",
    "CVE-2018-18559",
    "CVE-2018-19824",
    "CVE-2018-20511",
    "CVE-2018-5391",
    "CVE-2018-7740",
    "CVE-2019-6974",
    "CVE-2019-7221",
    "CVE-2019-7222"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1076)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A security flaw was found in the ip_frag_reasm()
    function in net/ipv4/ip_fragment.c in the Linux kernel
    which can cause a later system crash in
    ip_do_fragment(). With certain non-default, but
    non-rare, configuration of a victim host, an attacker
    can trigger this crash remotely, thus leading to a
    remote denial of service.(CVE-2018-14641)

  - A flaw named FragmentSmack was found in the way the
    Linux kernel handled reassembly of fragmented IPv4 and
    IPv6 packets. A remote attacker could use this flaw to
    trigger time and calculation expensive fragment
    reassembly algorithm by sending specially crafted
    packets which could lead to a CPU saturation and hence
    a denial of service on the system.(CVE-2018-5391)

  - The resv_map_release function in mm/hugetlb.c in the
    Linux kernel, through 4.15.7, allows local users to
    cause a denial of service (BUG) via a crafted
    application that makes mmap system calls and has a
    large pgoff argument to the remap_file_pages system
    call. (CVE-2018-7740)

  - A use-after-free vulnerability was found in the way the
    Linux kernel's KVM hypervisor emulates a preemption
    timer for L2 guests when nested (=1) virtualization is
    enabled. This high resolution timer(hrtimer) runs when
    a L2 guest is active. After VM exit, the sync_vmcs12()
    timer object is stopped. The use-after-free occurs if
    the timer object is freed before calling sync_vmcs12()
    routine. A guest user/process could use this flaw to
    crash the host kernel resulting in a denial of service
    or, potentially, gain privileged access to a system.
    (CVE-2019-7221)

  - An information leakage issue was found in the way Linux
    kernel's KVM hypervisor handled page fault exceptions
    while emulating instructions like VMXON, VMCLEAR,
    VMPTRLD, and VMWRITE with memory address as an operand.
    It occurs if the operand is a mmio address, as the
    returned exception object holds uninitialized stack
    memory contents. A guest user/process could use this
    flaw to leak host's stack memory contents to a guest.
    (CVE-2019-7222)

  - The xfs_dinode_verify function in
    fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel can
    cause a NULL pointer dereference in
    xfs_ilock_attr_map_shared function. An attacker could
    trick a legitimate user or a privileged attacker could
    exploit this by mounting a crafted xfs filesystem image
    to cause a kernel panic and thus a denial of service.
    (CVE-2018-10322)

  - The Linux kernel is vulnerable to a NULL pointer
    dereference in the
    ext4/mballoc.c:ext4_process_freed_data() function. An
    attacker could trick a legitimate user or a privileged
    attacker could exploit this by mounting a crafted ext4
    image to cause a kernel panic.(CVE-2018-1092)

  - The Linux kernel is vulnerable to a NULL pointer
    dereference in the ext4/xattr.c:ext4_xattr_inode_hash()
    function. An attacker could trick a legitimate user or
    a privileged attacker could exploit this to cause a
    NULL pointer dereference with a crafted ext4 image.
    (CVE-2018-1094)

  - An issue was discovered in the XFS filesystem in
    fs/xfs/libxfs/xfs_attr_leaf.c in the Linux kernel. A
    NULL pointer dereference may occur for a corrupted xfs
    image after xfs_da_shrink_inode() is called with a NULL
    bp. This can lead to a system crash and a denial of
    service. (CVE-2018-13094)

  - A flaw was found in the Linux kernel with files on
    tmpfs and hugetlbfs. An attacker is able to bypass file
    permissions on filesystems mounted with tmpfs/hugetlbs
    to modify a file and possibly disrupt normal system
    behavior. At this time there is an understanding there
    is no crash or privilege escalation but the impact of
    modifications on these filesystems of files in
    production systems may have adverse affects.
    (CVE-2018-18397)

  - A use-after-free flaw can occur in the Linux kernel due
    to a race condition between packet_do_bind() and
    packet_notifier() functions called for an AF_PACKET
    socket. An unprivileged, local user could use this flaw
    to induce kernel memory corruption on the system,
    leading to an unresponsive system or to a crash. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out. (CVE-2018-18559)

  - A flaw was found In the Linux kernel, through version
    4.19.6, where a local user could exploit a
    use-after-free in the ALSA driver by supplying a
    malicious USB Sound device (with zero interfaces) that
    is mishandled in usb_audio_probe in sound/usb/card.c.
    An attacker could corrupt memory and possibly escalate
    privileges if the attacker is able to have physical
    access to the system.(CVE-2018-19824)

  - An issue was discovered in the Linux kernel before
    4.18.11. The ipddp_ioctl function in
    drivers/net/appletalk/ipddp.c allows local users to
    obtain sensitive kernel address information by
    leveraging CAP_NET_ADMIN to read the ipddp_route dev
    and next fields via an SIOCFINDIPDDPRT ioctl call.
    (CVE-2018-20511)

  - A use-after-free vulnerability was found in the way the
    Linux kernel's KVM hypervisor implements its device
    control API. While creating a device via
    kvm_ioctl_create_device(), the device holds a reference
    to a VM object, later this reference is transferred to
    the caller's file descriptor table. If such file
    descriptor was to be closed, reference count to the VM
    object could become zero, potentially leading to a
    use-after-free issue. A user/process could use this
    flaw to crash the guest VM resulting in a denial of
    service issue or, potentially, gain privileged access
    to a system. (CVE-2019-6974)

  - Since Linux kernel version 3.2, the mremap() syscall
    performs TLB flushes after dropping pagetable locks. If
    a syscall such as ftruncate() removes entries from the
    pagetables of a task that is in the middle of mremap(),
    a stale TLB entry can remain for a short time that
    permits access to a physical page after it has been
    released back to the page allocator and
    reused.(CVE-2018-18281)

  - A division-by-zero in set_termios(), when debugging is
    enabled, was found in the Linux kernel. When the
    [io_ti] driver is loaded, a local unprivileged attacker
    can request incorrect high transfer speed in the
    change_port_settings() in the
    drivers/usb/serial/io_ti.c so that the divisor value
    becomes zero and causes a system crash resulting in a
    denial of service. (CVE-2017-18360)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1076
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "kernel-debuginfo-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "kernel-debuginfo-common-x86_64-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "perf-3.10.0-862.14.0.1.h85.eulerosv2r7",
        "python-perf-3.10.0-862.14.0.1.h85.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
