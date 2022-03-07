#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4019-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126065);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/20 11:24:23");

  script_cve_id("CVE-2016-6153", "CVE-2017-10989", "CVE-2017-13685", "CVE-2017-2518", "CVE-2017-2519", "CVE-2017-2520", "CVE-2018-20346", "CVE-2018-20505", "CVE-2018-20506", "CVE-2019-8457", "CVE-2019-9936", "CVE-2019-9937");
  script_xref(name:"USN", value:"4019-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : sqlite3 vulnerabilities (USN-4019-1)");
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
"It was discovered that SQLite incorrectly handled certain SQL files.
An attacker could possibly use this issue to execute arbitrary code or
cause a denial of service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-2518, CVE-2017-2520)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2018-20505)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu
18.10. (CVE-2018-20346, CVE-2018-20506)

It was discovered that SQLite incorrectly handled certain inputs. An
attacker could possibly use this issue to access sensitive
information. (CVE-2019-8457)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could possibly use this issue to access sensitive
information. This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04
LTS and Ubuntu 18.10. (CVE-2019-9936)

It was discovered that SQLite incorrectly handled certain inputs. An
attacker could possibly use this issue to cause a crash or execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS, Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2019-9937)

It was discovered that SQLite incorrectly handled certain inputs. An
attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 16.04 LTS. (CVE-2016-6153)

It was discovered that SQLite incorrectly handled certain databases.
An attacker could possibly use this issue to access sensitive
information. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-10989)

It was discovered that SQLite incorrectly handled certain files. An
attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 16.04 LTS. (CVE-2017-13685)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could possibly use this issue to execute arbitrary code or
cause a denial of service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-2519).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4019-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsqlite3-0 and / or sqlite3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sqlite3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/20");
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

if (ubuntu_check(osver:"16.04", pkgname:"libsqlite3-0", pkgver:"3.11.0-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"sqlite3", pkgver:"3.11.0-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libsqlite3-0", pkgver:"3.22.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"sqlite3", pkgver:"3.22.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libsqlite3-0", pkgver:"3.24.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"sqlite3", pkgver:"3.24.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libsqlite3-0", pkgver:"3.27.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"sqlite3", pkgver:"3.27.2-2ubuntu0.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsqlite3-0 / sqlite3");
}
