#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4043-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126445);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/09 10:56:49");

  script_cve_id("CVE-2019-12308", "CVE-2019-12781");
  script_xref(name:"USN", value:"4043-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : python-django vulnerabilities (USN-4043-1)");
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
"It was discovered that Django incorrectly handled certain inputs. An
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS, Ubuntu 18.10 and Ubuntu 19.04.
(CVE-2019-12308)

Gavin Wahl discovered that Django incorrectly handled certain
requests. An attacker could possibly use this issue to bypass
credentials and access administrator interface. (CVE-2019-12781).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4043-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django and / or python3-django packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/02");
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

if (ubuntu_check(osver:"16.04", pkgname:"python-django", pkgver:"1.8.7-1ubuntu5.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3-django", pkgver:"1.8.7-1ubuntu5.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python-django", pkgver:"1:1.11.11-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python3-django", pkgver:"1:1.11.11-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"python-django", pkgver:"1:1.11.15-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"python3-django", pkgver:"1:1.11.15-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python-django", pkgver:"1:1.11.20-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python3-django", pkgver:"1:1.11.20-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-django / python3-django");
}
