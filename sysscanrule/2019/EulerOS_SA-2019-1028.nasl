#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122201);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:24");

  script_cve_id(
    "CVE-2013-3076",
    "CVE-2018-10878",
    "CVE-2018-10880",
    "CVE-2018-10881",
    "CVE-2018-1108",
    "CVE-2018-14633",
    "CVE-2018-14646",
    "CVE-2018-16658",
    "CVE-2018-17972",
    "CVE-2018-18386",
    "CVE-2018-18690",
    "CVE-2019-3701"
  );
  script_bugtraq_id(
    59398
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1028)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bounds write and a
    denial of service or unspecified other impact is
    possible by mounting and operating a crafted ext4
    filesystem image.(CVE-2018-10878)

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

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound access in
    ext4_get_group_info function, a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image.(CVE-2018-10881)

  - A flaw was found in the Linux kernel's ext4 filesystem
    code. A stack-out-of-bounds write in
    ext4_update_inline_data() is possible when mounting and
    writing to a crafted ext4 image. An attacker could use
    this to cause a system crash and a denial of
    service.(CVE-2018-10880)

  - The crypto API in the Linux kernel through 3.9-rc8 does
    not initialize certain length variables, which allows
    local users to obtain sensitive information from kernel
    stack memory via a crafted recvmsg or recvfrom system
    call, related to the hash_recvmsg function in
    crypto/algif_hash.c and the skcipher_recvmsg function
    in crypto/algif_skcipher.c.(CVE-2013-3076)

  - weakness was found in the Linux kernel's implementation
    of random seed data. Programs, early in the boot
    sequence, could use the data allocated for the seed
    before it was sufficiently generated.(CVE-2018-1108)

  - An issue was discovered in the proc_pid_stack function
    in fs/proc/base.c in the Linux kernel. An attacker with
    a local account can trick the stack unwinder code to
    leak stack contents to userspace. The fix allows only
    root to inspect the kernel stack of an arbitrary
    task.(CVE-2018-17972)

  - A security flaw was found in the
    chap_server_compute_md5() function in the ISCSI target
    code in the Linux kernel in a way an authentication
    request from an ISCSI initiator is processed. An
    unauthenticated remote attacker can cause a stack
    buffer overflow and smash up to 17 bytes of the stack.
    The attack requires the iSCSI target to be enabled on
    the victim host. Depending on how the target's code was
    built (i.e. depending on a compiler, compile flags and
    hardware architecture) an attack may lead to a system
    crash and thus to a denial of service or possibly to a
    non-authorized access to data exported by an iSCSI
    target. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is highly unlikely.(CVE-2018-14633)

  - An issue was discovered in the Linux kernel before
    4.18.6. An information leak in cdrom_ioctl_drive_status
    in drivers/cdrom/cdrom.c could be used by local
    attackers to read kernel memory because a cast from
    unsigned long to int interferes with bounds
    checking.(CVE-2018-16658)

  - In the Linux kernel before 4.17, a local attacker able
    to set attributes on an xfs filesystem could make this
    filesystem non-operational until the next mount by
    triggering an unchecked error condition during an xfs
    attribute change, because xfs_attr_shortform_addname in
    fs/xfs/libxfs/xfs_attr.c mishandles ATTR_REPLACE
    operations with conversion of an attr from short to
    long form.(CVE-2018-18690)

  - A security flaw was found in the Linux kernel in
    drivers/tty/n_tty.c which allows local attackers (ones
    who are able to access pseudo terminals) to lock them
    up and block further usage of any pseudo terminal
    devices due to an EXTPROC versus ICANON confusion in
    TIOCINQ handler.(CVE-2018-18386)

  - The Linux kernel was found to be vulnerable to a NULL
    pointer dereference bug in the __netlink_ns_capable()
    function in the net/netlink/af_netlink.c file. A local
    attacker could exploit this when a net namespace with a
    netnsid is assigned to cause a kernel panic and a
    denial of service.(CVE-2018-14646)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1028
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

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

pkgs = ["kernel-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "kernel-debuginfo-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "kernel-debuginfo-common-x86_64-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "perf-3.10.0-862.14.0.1.h80.eulerosv2r7",
        "python-perf-3.10.0-862.14.0.1.h80.eulerosv2r7"];

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
