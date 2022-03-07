#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125514);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2018-1000204",
    "CVE-2018-10882",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2018-16884",
    "CVE-2018-18710",
    "CVE-2018-19985",
    "CVE-2018-20511",
    "CVE-2018-9516",
    "CVE-2018-9568",
    "CVE-2019-11091",
    "CVE-2019-11190",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-7222",
    "CVE-2019-9213"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2019-1587)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A malformed SG_IO ioctl issued for a SCSI device in the
    Linux kernel leads to a local kernel data leak
    manifesting in up to approximately 1000 memory pages
    copied to the userspace. The problem has limited scope
    as non-privileged users usually have no permissions to
    access SCSI device files.(CVE-2018-1000204)

  - A flaw in the load_elf_binary() function in the Linux
    kernel allows a local attacker to leak the base address
    of .text and stack sections for setuid binaries and
    bypass ASLR because install_exec_creds() is called too
    late in this function.(CVE-2019-11190)

  - A flaw was found in the Linux kernel in the
    hid_debug_events_read() function in the
    drivers/hid/hid-debug.c file. A lack of the certain
    checks may allow a privileged user ('root') to achieve
    an out-of-bounds write and thus receiving user space
    buffer corruption.(CVE-2018-9516)

  - A flaw was found in the Linux kernel's NFS41+
    subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process()
    use wrong back-channel IDs and cause a use-after-free
    vulnerability. Thus a malicious container user can
    cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out.(CVE-2018-16884)

  - An issue was discovered in the Linux kernel through
    4.19. An information leak in cdrom_ioctl_select_disc in
    drivers/cdrom/cdrom.c could be used by local attackers
    to read kernel memory because a cast from unsigned long
    to int interferes with bounds checking. This is similar
    to CVE-2018-10940 and CVE-2018-16658.(CVE-2018-18710)

  - A flaw was found in the Linux kernel in the function
    hso_probe() which reads if_num value from the USB
    device (as an u8) and uses it without a length check to
    index an array, resulting in an OOB memory read in
    hso_probe() or hso_get_config_data(). An attacker with
    a forged USB device and physical access to a system
    (needed to connect such a device) can cause a system
    crash and a denial of service.(CVE-2018-19985)

  - A possible memory corruption due to a type confusion
    was found in the Linux kernel in the sk_clone_lock()
    function in the net/core/sock.c. The possibility of
    local escalation of privileges cannot be fully ruled
    out for a local unprivileged attacker.(CVE-2018-9568)

  - A flaw was found in the Linux kernels implementation of
    Logical link control and adaptation protocol (L2CAP),
    part of the Bluetooth stack. An attacker with physical
    access within the range of standard Bluetooth
    transmission can create a specially crafted packet. The
    response to this specially crafted packet can contain
    part of the kernel stack which can be used in a further
    attack.(CVE-2019-3459)

  - A flaw was found in the Linux kernel's implementation
    of logical link control and adaptation protocol
    (L2CAP), part of the Bluetooth stack in the
    l2cap_parse_conf_rsp and l2cap_parse_conf_req
    functions. An attacker with physical access within the
    range of standard Bluetooth transmission can create a
    specially crafted packet. The response to this
    specially crafted packet can contain part of the kernel
    stack which can be used in a further
    attack.(CVE-2019-3460)

  - An information leakage issue was found in the way Linux
    kernel's KVM hypervisor handled page fault exceptions
    while emulating instructions like VMXON, VMCLEAR,
    VMPTRLD, and VMWRITE with memory address as an operand.
    It occurs if the operand is a mmio address, as the
    returned exception object holds uninitialized stack
    memory contents. A guest user/process could use this
    flaw to leak host's stack memory contents to a guest.
    (CVE-2019-7222)

  - A flaw was found in mmap in the Linux kernel allowing
    the process to map a null page. This allows attackers
    to abuse this mechanism to turn null pointer
    dereferences into workable exploits(CVE-2019-9213)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound write in the
    fs/jbd2/transaction.c code, a denial of service, and a
    system crash by unmounting a crafted ext4 filesystem
    image.(CVE-2018-10882)

  - An issue was discovered in the Linux kernel before
    4.18.11. The ipddp_ioctl function in
    drivers/net/appletalk/ipddp.c allows local users to
    obtain sensitive kernel address information by
    leveraging CAP_NET_ADMIN to read the ipddp_route dev
    and next fields via an SIOCFINDIPDDPRT ioctl call.
    (CVE-2018-20511)

  - A flaw was found in the implementation of the 'fill
    buffer', a mechanism used by modern CPUs when a
    cache-miss is made on L1 CPU cache. If an attacker can
    generate a load operation that would create a page
    fault, the execution will continue speculatively with
    incorrect data from the fill buffer while the data is
    fetched from higher level caches. This response time
    can be measured to infer data in the fill buffer.
    (CVE-2018-12130)

  - Modern Intel microprocessors implement hardware-level
    micro-optimizations to improve the performance of
    writing data back to CPU caches. The write operation is
    split into STA (STore Address) and STD (STore Data)
    sub-operations. These sub-operations allow the
    processor to hand-off address generation logic into
    these sub-operations for optimized writes. Both of
    these sub-operations write to a shared distributed
    processor structure called the 'processor store
    buffer'. As a result, an unprivileged attacker could
    use this flaw to read private data resident within the
    CPU's processor store buffer. (CVE-2018-12126)

  - Microprocessors use a 'load port' subcomponent to
    perform load operations from memory or IO. During a
    load operation, the load port receives data from the
    memory or IO subsystem and then provides the data to
    the CPU registers and operations in the CPU's
    pipelines. Stale load operations results are stored in
    the 'load port' table until overwritten by newer
    operations. Certain load-port operations triggered by
    an attacker can be used to reveal data about previous
    stale requests leaking data back to the attacker via a
    timing side-channel. (CVE-2018-12127)

  - Uncacheable memory on some microprocessors utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access. (CVE-2019-11091)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1587
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h193",
        "kernel-debuginfo-3.10.0-514.44.5.10.h193",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h193",
        "kernel-devel-3.10.0-514.44.5.10.h193",
        "kernel-headers-3.10.0-514.44.5.10.h193",
        "kernel-tools-3.10.0-514.44.5.10.h193",
        "kernel-tools-libs-3.10.0-514.44.5.10.h193",
        "perf-3.10.0-514.44.5.10.h193",
        "python-perf-3.10.0-514.44.5.10.h193"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
