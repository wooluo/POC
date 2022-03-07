#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124978);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-7264",
    "CVE-2014-4322",
    "CVE-2014-4653",
    "CVE-2014-9900",
    "CVE-2015-2666",
    "CVE-2015-8543",
    "CVE-2016-10208",
    "CVE-2016-2063",
    "CVE-2016-3135",
    "CVE-2016-6187",
    "CVE-2016-8666",
    "CVE-2016-9191",
    "CVE-2017-16538",
    "CVE-2017-5551",
    "CVE-2017-7618",
    "CVE-2017-9077",
    "CVE-2018-14734",
    "CVE-2019-10124",
    "CVE-2019-7221",
    "CVE-2019-7308"
  );
  script_bugtraq_id(
    64685,
    68164,
    73183
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1525)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Mounting a crafted EXT4 image read-only leads to an
    attacker controlled memory corruption and
    SLAB-Out-of-Bounds reads.(CVE-2016-10208)

  - An issue was discovered in the hwpoison implementation
    in mm/memory-failure.c in the Linux kernel before
    5.0.4. When soft_offline_in_use_page() runs on a thp
    tail page after pmd is split, an attacker can cause a
    denial of service (BUG).(CVE-2019-10124)

  - A stack-based buffer overflow flaw was found in the
    Linux kernel's early load microcode functionality. On a
    system with UEFI Secure Boot enabled, a local,
    privileged user could use this flaw to increase their
    privileges to the kernel (ring0) level, bypassing
    intended restrictions in place.(CVE-2015-2666)

  - A flaw was found in the way the Linux kernel's
    networking subsystem handled offloaded packets with
    multiple layers of encapsulation in the GRO (Generic
    Receive Offload) code path. A remote attacker could use
    this flaw to trigger unbounded recursion in the kernel
    that could lead to stack corruption, resulting in a
    system crash.(CVE-2016-8666)

  - The ethtool_get_wol function in net/core/ethtool.c in
    the Linux kernel through 4.7, as used in Android before
    2016-08-05 on Nexus 5 and 7 (2013) devices, does not
    initialize a certain data structure, which allows local
    users to obtain sensitive information via a crafted
    application, aka Android internal bug 28803952 and
    Qualcomm internal bug CR570754.(CVE-2014-9900)

  - A vulnerability was found in crypto/ahash.c in the
    Linux kernel which allows attackers to cause a denial
    of service (API operation calling its own callback, and
    infinite recursion) by triggering EBUSY on a full
    queue.(CVE-2017-7618)

  - drivers/misc/qseecom.c in the QSEECOM driver for the
    Linux kernel 3.x, as used in Qualcomm Innovation Center
    (QuIC) Android contributions for MSM devices and other
    products, does not validate certain offset, length, and
    base values within an ioctl call, which allows
    attackers to gain privileges or cause a denial of
    service (memory corruption) via a crafted
    application.(CVE-2014-4322)

  - An integer overflow vulnerability was found in the
    Linux kernel in xt_alloc_table_info, which on 32-bit
    systems can lead to small structure allocation and a
    copy_from_user based heap corruption.(CVE-2016-3135)

  - Stack-based buffer overflow in the
    supply_lm_input_write function in
    drivers/thermal/supply_lm_core.c in the MSM Thermal
    driver for the Linux kernel 3.x, as used in Qualcomm
    Innovation Center (QuIC) Android contributions for MSM
    devices and other products, allows attackers to cause a
    denial of service or possibly have unspecified other
    impact via a crafted application that sends a large
    amount of data through the debugfs
    interface.(CVE-2016-2063)

  - The l2tp_ip_recvmsg function in net/l2tp/l2tp_ip.c in
    the Linux kernel before 3.12.4 updates a certain length
    value before ensuring that an associated data structure
    has been initialized, which allows local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call.(CVE-2013-7264)

  - A bypass was found for the Spectre v1 hardening in the
    eBPF engine of the Linux kernel. The code in the
    kernel/bpf/verifier.c performs undesirable
    out-of-bounds speculation on pointer arithmetic in
    various cases, including cases of different branches
    with different state or limits to sanitize, leading to
    side-channel attacks.(CVE-2019-7308)

  - The tcp_v6_syn_recv_sock function in
    net/ipv6/tcp_ipv6.c in the Linux kernel mishandles
    inheritance, which allows local users to cause a denial
    of service or possibly have unspecified other impact
    via crafted system calls, a related issue to
    CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-9077)

  - The cgroup offline implementation in the Linux kernel
    through 4.8.11 mishandles certain drain operations,
    which allows local users to cause a denial of service
    (system hang) by leveraging access to a container
    environment for executing a crafted application, as
    demonstrated by trinity.(CVE-2016-9191)

  - The KVM implementation in the Linux kernel through
    4.20.5 has a Use-after-Free.(CVE-2019-7221)

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's network subsystem handled socket
    creation with an invalid protocol identifier. A local
    user could use this flaw to crash the
    system.(CVE-2015-8543)

  - The drivers/media/usb/dvb-usb-v2/lmedm04.c in the Linux
    kernel, through 4.13.11, allows local users to cause a
    denial of service (general protection fault and system
    crash) or possibly have unspecified other impact via a
    crafted USB device, related to a missing warm-start
    check and incorrect attach timing
    (dm04_lme2510_frontend_attach versus
    dm04_lme2510_tuner).(CVE-2017-16538)

  - A use-after-free flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4653)

  - A vulnerability leading to a local privilege escalation
    was found in apparmor in the Linux kernel. When
    proc_pid_attr_write() was changed to use memdup_user
    apparmor's (interface violating) assumption that the
    setprocattr buffer was always a single page was
    violated.(CVE-2016-6187)

  - A vulnerability was found in the Linux kernel in
    'tmpfs' file system. When file permissions are modified
    via 'chmod' and the user is not in the owning group or
    capable of CAP_FSETID, the setgid bit is cleared in
    inode_change_ok(). Setting a POSIX ACL via 'setxattr'
    sets the file permissions as well as the new ACL, but
    doesn't clear the setgid bit in a similar way; this
    allows to bypass the check in 'chmod'.(CVE-2017-5551)

  - A flaw was found in the Linux Kernel in the
    ucma_leave_multicast() function in
    drivers/infiniband/core/ucma.c which allows access to a
    certain data structure after freeing it in
    ucma_process_join(). This allows an attacker to cause a
    use-after-free bug and to induce kernel memory
    corruption, leading to a system crash or other
    unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-14734)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1525
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
