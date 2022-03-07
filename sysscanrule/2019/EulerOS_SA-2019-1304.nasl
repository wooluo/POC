#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124431);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2017-13168",
    "CVE-2018-10877",
    "CVE-2018-16884",
    "CVE-2018-19985",
    "CVE-2018-9422",
    "CVE-2019-11190",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-6133"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1304)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An elevation of privilege vulnerability in the kernel
    scsi driver. Product: Android. Versions: Android
    kernel. Android ID A-65023233.(CVE-2017-13168)

  - Non-optimized code for key handling of shared futexes
    was found in the Linux kernel in the form of unbounded
    contention time due to the page lock for real-time
    users. Before the fix, the page lock was an
    unnecessarily heavy lock for the futex path that
    protected too much. After the fix, the page lock is
    only required in a specific corner case.(CVE-2018-9422)

  - A flaw in the load_elf_binary() function in the Linux
    kernel allows a local attacker to leak the base address
    of .text and stack sections for setuid binaries and
    bypass ASLR because install_exec_creds() is called too
    late in this function.(CVE-2019-11190)

  - A flaw was found in the Linux kernel ext4 filesystem.
    An out-of-bound access is possible in the
    ext4_ext_drop_refs() function when operating on a
    crafted ext4 filesystem image.(CVE-2018-10877)

  - A vulnerability was found in polkit. When
    authentication is performed by a non-root user to
    perform an administrative task, the authentication is
    temporarily cached in such a way that a local attacker
    could impersonate the authorized process, thus gaining
    access to elevated privileges.(CVE-2019-6133)

  - A flaw was found in the Linux kernel in the function
    hso_probe() which reads if_num value from the USB
    device (as an u8) and uses it without a length check to
    index an array, resulting in an OOB memory read in
    hso_probe() or hso_get_config_data(). An attacker with
    a forged USB device and physical access to a system
    (needed to connect such a device) can cause a system
    crash and a denial of service.(CVE-2018-19985)

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

  - A flaw was found in the Linux kernels implementation of
    Logical link control and adaptation protocol (L2CAP),
    part of the Bluetooth stack. An attacker with physical
    access within the range of standard Bluetooth
    transmission can create a specially crafted packet. The
    response to this specially crafted packet can contain
    part of the kernel stack which can be used in a further
    attack.(CVE-2019-3459)

  - A flaw was found in the Linux kernel's NFS41+
    subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process()
    use wrong back-channel IDs and cause a use-after-free
    vulnerability. Thus a malicious container user can
    cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out.(CVE-2018-16884)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1304
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/01");

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

pkgs = ["kernel-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "kernel-debuginfo-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "kernel-debuginfo-common-x86_64-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "perf-3.10.0-862.14.0.1.h137.eulerosv2r7",
        "python-perf-3.10.0-862.14.0.1.h137.eulerosv2r7"];

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
