#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126299);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/02 12:46:54");

  script_cve_id(
    "CVE-2018-20836",
    "CVE-2018-7191",
    "CVE-2019-11477",
    "CVE-2019-11478",
    "CVE-2019-11479",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-3901",
    "CVE-2019-6133"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2019-1672)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An integer overflow flaw was found in the way the Linux
    kernel's networking subsystem processed TCP Selective
    Acknowledgment (SACK) segments. While processing SACK
    segments, the Linux kernel's socket buffer (SKB) data
    structure becomes fragmented. Each fragment is about
    TCP maximum segment size (MSS) bytes. To efficiently
    process SACK blocks, the Linux kernel merges multiple
    fragmented SKBs into one, potentially overflowing the
    variable holding the number of segments. A remote
    attacker could use this flaw to crash the Linux kernel
    by sending a crafted sequence of SACK segments on a TCP
    connection with small value of TCP MSS, resulting in a
    denial of service (DoS). (CVE-2019-11477)

  - Kernel: tcp: excessive resource consumption while
    processing SACK blocks allows remote denial of service
    (CVE-2019-11478)

  - Kernel: tcp: excessive resource consumption for TCP
    connections with low MSS allows remote denial of
    service (CVE-2019-11479)

  - In the tun subsystem in the Linux kernel before
    4.13.14, dev_get_valid_name is not called before
    register_netdevice. This allows local users to cause a
    denial of service (NULL pointer dereference and panic)
    via an ioctl(TUNSETIFF) call with a dev name containing
    a / character. This is similar to
    CVE-2013-4343.(CVE-2018-7191)

  - A flaw was found in the Linux kernel where the coredump
    implementation does not use locking or other mechanisms
    to prevent vma layout or vma flags changes while it
    runs. This allows local users to obtain sensitive
    information, cause a denial of service (DoS), or
    possibly have unspecified other impact by triggering a
    race condition with mmget_not_zero or get_task_mm
    calls.(CVE-2019-11599)

  - An issue was discovered in the Linux kernel before
    4.20. There is a race condition in smp_task_timedout()
    and smp_task_done() in
    drivers/scsi/libsas/sas_expander.c, leading to a
    use-after-free.(CVE-2018-20836)

  - A race condition in perf_event_open() allows local
    attackers to leak sensitive data from setuid programs.
    As no relevant locks (in particular the
    cred_guard_mutex) are held during the
    ptrace_may_access() call, it is possible for the
    specified target task to perform an execve() syscall
    with setuid execution before perf_event_alloc()
    actually attaches to it, allowing an attacker to bypass
    the ptrace_may_access() check and the
    perf_event_exit_task(current) call that is performed in
    install_exec_creds() during privileged execve()
    calls.(CVE-2019-3901)

  - A flaw was found in the Linux kernel, prior to version
    5.0.7, in drivers/scsi/megaraid/megaraid_sas_base.c,
    where a NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in
    megasas_alloc_cmds(). An attacker can crash the system
    if they were able to load the megaraid_sas kernel
    module and groom memory beforehand, leading to a denial
    of service (DoS), related to a
    use-after-free.(CVE-2019-11810)

  - A vulnerability was found in polkit. When
    authentication is performed by a non-root user to
    perform an administrative task, the authentication is
    temporarily cached in such a way that a local attacker
    could impersonate the authorized process, thus gaining
    access to elevated privileges.(CVE-2019-6133)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1672
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/27");

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

pkgs = ["kernel-3.10.0-514.44.5.10.h198",
        "kernel-debuginfo-3.10.0-514.44.5.10.h198",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h198",
        "kernel-devel-3.10.0-514.44.5.10.h198",
        "kernel-headers-3.10.0-514.44.5.10.h198",
        "kernel-tools-3.10.0-514.44.5.10.h198",
        "kernel-tools-libs-3.10.0-514.44.5.10.h198",
        "perf-3.10.0-514.44.5.10.h198",
        "python-perf-3.10.0-514.44.5.10.h198"];

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
