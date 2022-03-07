#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125513);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2017-13168",
    "CVE-2018-10877",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2018-16884",
    "CVE-2018-9422",
    "CVE-2018-9516",
    "CVE-2019-11091",
    "CVE-2019-11190",
    "CVE-2019-3874",
    "CVE-2019-6133"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2019-1586)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Linux kernel's NFS41+
    subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process()
    use wrong back-channel IDs and cause a use-after-free
    vulnerability. Thus a malicious container user can
    cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out.(CVE-2018-16884)

  - An elevation of privilege vulnerability in the kernel
    scsi driver. Product: Android. Versions: Android
    kernel. Android ID A-65023233.(CVE-2017-13168)

  - A flaw in the load_elf_binary() function in the Linux
    kernel allows a local attacker to leak the base address
    of .text and stack sections for setuid binaries and
    bypass ASLR because install_exec_creds() is called too
    late in this function.(CVE-2019-11190)

  - The SCTP socket buffer used by a userspace application
    is not accounted by the cgroups subsystem. An attacker
    can use this flaw to cause a denial of service
    attack.(CVE-2019-3874)

  - A flaw was found in the Linux kernel ext4 filesystem.
    An out-of-bound access is possible in the
    ext4_ext_drop_refs() function when operating on a
    crafted ext4 filesystem image.(CVE-2018-10877)

  - Non-optimized code for key handling of shared futexes
    was found in the Linux kernel in the form of unbounded
    contention time due to the page lock for real-time
    users. Before the fix, the page lock was an
    unnecessarily heavy lock for the futex path that
    protected too much. After the fix, the page lock is
    only required in a specific corner case.(CVE-2018-9422)

  - A flaw was found in the Linux kernel in the
    hid_debug_events_read() function in the
    drivers/hid/hid-debug.c file. A lack of the certain
    checks may allow a privileged user ('root') to achieve
    an out-of-bounds write and thus receiving user space
    buffer corruption.(CVE-2018-9516)

  - A vulnerability was found in polkit. When
    authentication is performed by a non-root user to
    perform an administrative task, the authentication is
    temporarily cached in such a way that a local attacker
    could impersonate the authorized process, thus gaining
    access to elevated privileges.(CVE-2019-6133)

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
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1586
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.62.59.83.h154",
        "kernel-debug-3.10.0-327.62.59.83.h154",
        "kernel-debug-devel-3.10.0-327.62.59.83.h154",
        "kernel-debuginfo-3.10.0-327.62.59.83.h154",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h154",
        "kernel-devel-3.10.0-327.62.59.83.h154",
        "kernel-headers-3.10.0-327.62.59.83.h154",
        "kernel-tools-3.10.0-327.62.59.83.h154",
        "kernel-tools-libs-3.10.0-327.62.59.83.h154",
        "perf-3.10.0-327.62.59.83.h154",
        "python-perf-3.10.0-327.62.59.83.h154"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
