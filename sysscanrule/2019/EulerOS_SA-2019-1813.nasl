#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128105);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/23 10:01:44");

  script_cve_id(
    "CVE-2019-10639"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1813)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerability :

  - The Linux kernel 4.x (starting from 4.1) and 5.x before
    5.0.8 allows Information Exposure (partial kernel
    address disclosure), leading to a KASLR bypass.
    Specifically, it is possible to extract the KASLR
    kernel image offset using the IP ID values the kernel
    produces for connection-less protocols (e.g., UDP and
    ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). This
    key contains enough bits from a kernel address (of a
    static variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is
    exposed. This attack can be carried out remotely, by
    the attacker forcing the target device to send UDP or
    ICMP (or certain other) traffic to attacker-controlled
    IP addresses. Forcing a server to send UDP traffic is
    trivial if the server is a DNS server. ICMP traffic is
    trivial if the server answers ICMP Echo requests
    (ping). For client targets, if the target visits the
    attacker's web page, then WebRTC or gQUIC can be used
    to force UDP traffic to attacker-controlled IP
    addresses. NOTE: this attack against KASLR became
    viable in 4.1 because IP ID generation was changed to
    have a dependency on an address associated with a
    network namespace.(CVE-2019-10639)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1813
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

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

pkgs = ["kernel-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "kernel-debuginfo-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "kernel-debuginfo-common-x86_64-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "perf-3.10.0-862.14.1.1.h224.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.1.h224.eulerosv2r7"];

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
