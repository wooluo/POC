#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124972);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-4350",
    "CVE-2014-3182",
    "CVE-2014-8173",
    "CVE-2014-9895",
    "CVE-2015-1328",
    "CVE-2015-2042",
    "CVE-2015-4178",
    "CVE-2015-5157",
    "CVE-2016-0723",
    "CVE-2016-4998",
    "CVE-2016-7911",
    "CVE-2017-17712",
    "CVE-2017-2584",
    "CVE-2017-7187",
    "CVE-2017-8890",
    "CVE-2018-10021",
    "CVE-2018-10322",
    "CVE-2018-1091",
    "CVE-2018-13096",
    "CVE-2019-3701"
  );
  script_bugtraq_id(
    62405,
    69770,
    72730,
    73133,
    75206,
    76005
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1519)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The IPv6 SCTP implementation in net/sctp/ipv6.c in the
    Linux kernel through 3.11.1 uses data structures and
    function calls that do not trigger an intended
    configuration of IPsec encryption, which allows remote
    attackers to obtain sensitive information by sniffing
    the network.(CVE-2013-4350)

  - The sg_ioctl function in drivers/scsi/sg.c in the Linux
    kernel allows local users to cause a denial of service
    (stack-based buffer overflow) or possibly have
    unspecified other impacts via a large command size in
    an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds
    write access in the sg_write function.(CVE-2017-7187)

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

  - net/rds/sysctl.c in the Linux kernel before 3.19 uses
    an incorrect data type in a sysctl table, which allows
    local users to obtain potentially sensitive information
    from kernel memory or possibly have unspecified other
    impact by accessing a sysctl entry.(CVE-2015-2042)

  - The inet_csk_clone_lock function in
    net/ipv4/inet_connection_sock.c in the Linux kernel
    allows attackers to cause a denial of service (double
    free) or possibly have unspecified other impact by
    leveraging use of the accept system call. An
    unprivileged local user could use this flaw to induce
    kernel memory corruption on the system, leading to a
    crash. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.(CVE-2017-8890)

  - The overlayfs implementation in the linux (aka Linux
    kernel) package before 3.19.0-21.21 in Ubuntu through
    15.04 does not properly check permissions for file
    creation in the upper filesystem directory, which
    allows local users to obtain root access by leveraging
    a configuration in which overlayfs is permitted in an
    arbitrary mount namespace.(CVE-2015-1328)

  - The xfs_dinode_verify function in
    fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel
    through 4.16.3 allows local users to cause a denial of
    service (xfs_ilock_attr_map_shared invalid pointer
    dereference) via a crafted xfs image.(CVE-2018-10322)

  - In the flush_tmregs_to_thread function in
    arch/powerpc/kernel/ptrace.c in the Linux kernel before
    4.13.5, a guest kernel crash can be triggered from
    unprivileged userspace during a core dump on a POWER
    host due to a missing processor feature check and an
    erroneous use of transactional memory (TM) instructions
    in the core dump path, leading to a denial of
    service.(CVE-2018-1091)

  - ** DISPUTED ** drivers/scsi/libsas/sas_scsi_host.c in
    the Linux kernel before 4.16 allows local users to
    cause a denial of service (ata qc leak) by triggering
    certain failure conditions. NOTE: a third party
    disputes the relevance of this report because the
    failure can only occur for physically proximate
    attackers who unplug SAS Host Bus Adapter
    cables.(CVE-2018-10021)

  - A use-after-free flaw was discovered in the Linux
    kernel's tty subsystem, which allows for the disclosure
    of uncontrolled memory location and possible kernel
    panic. The information leak is caused by a race
    condition when attempting to set and read the tty line
    discipline. A local attacker could use the TIOCSETD
    (via tty_set_ldisc ) to switch to a new line
    discipline; a concurrent call to a TIOCGETD ioctl
    performing a read on a given tty could then access
    previously allocated memory. Up to 4 bytes could be
    leaked when querying the line discipline or the kernel
    could panic with a NULL-pointer
    dereference.(CVE-2016-0723)

  - An out-of-bounds read flaw was found in the way the
    Logitech Unifying receiver driver handled HID reports
    with an invalid device_index value. An attacker with
    physical access to the system could use this flaw to
    crash the system or, potentially, escalate their
    privileges on the system.(CVE-2014-3182)

  - arch/x86/kvm/emulate.c in the Linux kernel through
    4.9.3 allows local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (use-after-free) via a crafted application that
    leverages instruction emulation for fxrstor, fxsave,
    sgdt, and sidt.(CVE-2017-2584)

  - A flaw was found in the way the Linux kernel handled
    IRET faults during the processing of NMIs. An
    unprivileged, local user could use this flaw to crash
    the system or, potentially (although highly unlikely),
    escalate their privileges on the system.(CVE-2015-5157)

  - drivers/media/media-device.c in the Linux kernel before
    3.11, as used in Android before 2016-08-05 on Nexus 5
    and 7 (2013) devices, does not properly initialize
    certain data structures, which allows local users to
    obtain sensitive information via a crafted application,
    aka Android internal bug 28750150 and Qualcomm internal
    bug CR570757, a different vulnerability than
    CVE-2014-1739.(CVE-2014-9895)

  - A use-after-free vulnerability in sys_ioprio_get() was
    found due to get_task_ioprio() accessing the
    task->io_context without holding the task lock and
    could potentially race with exit_io_context(), leading
    to a use-after-free.(CVE-2016-7911)

  - A flaw was found in the Linux kernel which is related
    to the user namespace lazily unmounting file systems.
    The fs_pin struct has two members (m_list and s_list)
    which are usually initialized on use in the
    pin_insert_group function. However, these members might
    go unmodified; in this case, the system panics when it
    attempts to destroy or free them. This flaw could be
    used to launch a denial-of-service
    attack.(CVE-2015-4178)

  - A flaw was found in the Linux kernel's implementation
    of raw_sendmsg allowing a local attacker to panic the
    kernel or possibly leak kernel addresses. A local
    attacker, with the privilege of creating raw sockets,
    can abuse a possible race condition when setting the
    socket option to allow the kernel to automatically
    create ip header values and thus potentially escalate
    their privileges.(CVE-2017-17712)

  - A flaw was discovered in the F2FS filesystem code in
    fs/f2fs/super.c in the Linux kernel. A denial of
    service, due to an out-of-bounds memory access, can
    occur upon encountering an abnormal bitmap size when
    mounting a crafted f2fs image.(CVE-2018-13096)

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's madvise MADV_WILLNEED functionality
    handled page table locking. A local, unprivileged user
    could use this flaw to crash the system.(CVE-2014-8173)

  - An out-of-bounds heap memory access leading to a Denial
    of Service, heap disclosure, or further impact was
    found in setsockopt(). The function call is normally
    restricted to root, however some processes with
    cap_sys_admin may also be able to trigger this flaw in
    privileged container environments.(CVE-2016-4998)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1519
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Overlayfs Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

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
