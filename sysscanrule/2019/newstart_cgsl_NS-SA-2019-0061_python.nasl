#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0061. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127255);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id("CVE-2018-1060", "CVE-2018-1061", "CVE-2019-9636");
  script_bugtraq_id(107400);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : python Multiple Vulnerabilities (NS-SA-2019-0061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has python packages installed that are affected by
multiple vulnerabilities:

  - A flaw was found in the way catastrophic backtracking
    was implemented in python's pop3lib's apop() method. An
    attacker could use this flaw to cause denial of service.
    (CVE-2018-1060)

  - A flaw was found in the way catastrophic backtracking
    was implemented in python's difflib.IS_LINE_JUNK method.
    An attacker could use this flaw to cause denial of
    service. (CVE-2018-1061)

  - It was discovered that python's functions
    urllib.parse.urlsplit and urllib.parse.urlparse do not
    properly handle URLs encoded with
    Punycode/Internationalizing Domain Names in Applications
    (IDNA), which may result in a wrong domain name
    (specifically the netloc component of URL -
    user@domain:port) being returned by those functions.
    When an application parses user-supplied URLs to store
    cookies, authentication credentials, or other kind of
    information, it is possible for an attacker to provide
    specially crafted URLs to make the application locate
    host-related information (e.g. cookies, authentication
    data) and send them to a different host than where it
    should, unlike if the URLs had been correctly parsed.
    The result of an attack may vary based on the
    application. (CVE-2019-9636)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0061");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL python packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9636");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "python-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite",
    "python-debug-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite",
    "python-debuginfo-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite",
    "python-devel-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite",
    "python-libs-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite",
    "python-test-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite",
    "python-tools-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite",
    "tkinter-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47.lite"
  ],
  "CGSL MAIN 5.04": [
    "python-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47",
    "python-debug-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47",
    "python-debuginfo-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47",
    "python-devel-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47",
    "python-libs-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47",
    "python-test-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47",
    "python-tools-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47",
    "tkinter-2.7.5-77.el7_6.cgslv5.0.1.g1e06d47"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
