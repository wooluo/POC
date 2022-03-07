#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3990-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125338);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/22 10:34:57");

  script_cve_id("CVE-2018-20060", "CVE-2019-11236", "CVE-2019-11324");
  script_xref(name:"USN", value:"3990-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : python-urllib3 vulnerabilities (USN-3990-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that urllib3 incorrectly removed Authorization HTTP
headers when handled cross-origin redirects. This could result in
credentials being sent to unintended hosts. This issue only affected
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-20060)

It was discovered that urllib3 incorrectly stripped certain characters
from requests. A remote attacker could use this issue to perform CRLF
injection. (CVE-2019-11236)

It was discovered that urllib3 incorrectly handled situations where a
desired set of CA certificates were specified. This could result in
certificates being accepted by the default CA certificates contrary to
expectations. This issue only affected Ubuntu 18.04 LTS, Ubuntu 18.10,
and Ubuntu 19.04. (CVE-2019-11324).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3990-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-urllib3 and / or python3-urllib3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-urllib3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019 Canonical, Inc. / NASL script (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(16\.04|18\.04|18\.10|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 18.10 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"python-urllib3", pkgver:"1.13.1-2ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3-urllib3", pkgver:"1.13.1-2ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python-urllib3", pkgver:"1.22-1ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python3-urllib3", pkgver:"1.22-1ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"python-urllib3", pkgver:"1.22-1ubuntu0.18.10.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"python3-urllib3", pkgver:"1.22-1ubuntu0.18.10.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python-urllib3", pkgver:"1.24.1-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python3-urllib3", pkgver:"1.24.1-1ubuntu0.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-urllib3 / python3-urllib3");
}
