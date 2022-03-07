#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125515);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2017-14156",
    "CVE-2018-10876",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091",
    "CVE-2019-11486",
    "CVE-2019-11599",
    "CVE-2019-3901"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1588)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Linux kernel where the coredump
    implementation does not use locking or other mechanisms
    to prevent vma layout or vma flags changes while it
    runs. This allows local users to obtain sensitive
    information, cause a denial of service (DoS), or
    possibly have unspecified other impact by triggering a
    race condition with mmget_not_zero or get_task_mm
    calls.(CVE-2019-11599)

  - The Siemens R3964 line discipline driver in
    drivers/tty/n_r3964.c in the Linux kernel before 5.0.8
    has multiple race conditions.(CVE-2019-11486)

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

  - The atyfb_ioctl function in
    drivers/video/fbdev/aty/atyfb_base.c in the Linux
    kernel through 4.12.10 does not initialize a certain
    data structure, which allows local users to obtain
    sensitive information from kernel stack memory by
    reading locations associated with padding
    bytes.(CVE-2017-14156)

  - A flaw was found in the Linux kernel's ext4 filesystem
    code. A use-after-free is possible in
    ext4_ext_remove_space() function when mounting and
    operating a crafted ext4 image.(CVE-2018-10876)

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
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1588
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "kernel-debuginfo-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "kernel-debuginfo-common-x86_64-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "perf-3.10.0-862.14.0.1.h178.eulerosv2r7",
        "python-perf-3.10.0-862.14.0.1.h178.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
