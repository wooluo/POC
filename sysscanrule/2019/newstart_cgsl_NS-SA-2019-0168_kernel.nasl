#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0168. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127456);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2019-3896",
    "CVE-2019-11477",
    "CVE-2019-11478",
    "CVE-2019-11479"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0168)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - An integer overflow flaw was found in the way the Linux
    kernel's networking subsystem processed TCP Selective
    Acknowledgment (SACK) segments. While processing SACK
    segments, the Linux kernel's socket buffer (SKB) data
    structure becomes fragmented. Each fragment is about TCP
    maximum segment size (MSS) bytes. To efficiently process
    SACK blocks, the Linux kernel merges multiple fragmented
    SKBs into one, potentially overflowing the variable
    holding the number of segments. A remote attacker could
    use this flaw to crash the Linux kernel by sending a
    crafted sequence of SACK segments on a TCP connection
    with small value of TCP MSS, resulting in a denial of
    service (DoS). (CVE-2019-11477)

  - An excessive resource consumption flaw was found in the
    way the Linux kernel's networking subsystem processed
    TCP Selective Acknowledgment (SACK) segments. While
    processing SACK segments, the Linux kernel's socket
    buffer (SKB) data structure becomes fragmented, which
    leads to increased resource utilization to traverse and
    process these fragments as further SACK segments are
    received on the same TCP connection. A remote attacker
    could use this flaw to cause a denial of service (DoS)
    by sending a crafted sequence of SACK segments on a TCP
    connection. (CVE-2019-11478)

  - An excessive resource consumption flaw was found in the
    way the Linux kernel's networking subsystem processed
    TCP segments. If the Maximum Segment Size (MSS) of a TCP
    connection was set to low values, such as 48 bytes, it
    can leave as little as 8 bytes for the user data, which
    significantly increases the Linux kernel's resource
    (CPU, Memory, and Bandwidth) utilization. A remote
    attacker could use this flaw to cause a denial of
    service (DoS) by repeatedly sending network traffic on a
    TCP connection with low TCP MSS. (CVE-2019-11479)

  - A double-free can happen in idr_remove_all() in
    lib/idr.c in the Linux kernel. An unprivileged local
    attacker can use this flaw for a privilege escalation or
    for a system crash and a denial of service (DoS).
    (CVE-2019-3896)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0168");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3896");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "kernel-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-debug-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-debug-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-debuginfo-common-x86_64-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-devel-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-doc-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-firmware-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "kernel-headers-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "perf-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "python-perf-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e",
    "python-perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.134.g9e9387e"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
