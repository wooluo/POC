#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3937-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123787);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/12  9:50:26");

  script_cve_id("CVE-2018-17189", "CVE-2018-17199", "CVE-2019-0196", "CVE-2019-0211", "CVE-2019-0217", "CVE-2019-0220");
  script_xref(name:"USN", value:"3937-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 18.10 : apache2 vulnerabilities (USN-3937-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Charles Fol discovered that the Apache HTTP Server incorrectly handled
the scoreboard shared memory area. A remote attacker able to upload
and run scripts could possibly use this issue to execute arbitrary
code with root privileges. (CVE-2019-0211)

It was discovered that the Apache HTTP Server HTTP/2 module
incorrectly handled certain requests. A remote attacker could possibly
use this issue to cause the server to consume resources, leading to a
denial of service. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 18.10. (CVE-2018-17189)

It was discovered that the Apache HTTP Server incorrectly handled
session expiry times. When used with mod_session_cookie, this may
result in the session expiry time to be ignored, contrary to
expectations. (CVE-2018-17199)

Craig Young discovered that the Apache HTTP Server HTTP/2 module
incorrectly handled certain requests. A remote attacker could possibly
use this issue to cause the server to process requests incorrectly.
This issue only affected Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2019-0196)

Simon Kappel discovered that the Apache HTTP Server mod_auth_digest
module incorrectly handled threads. A remote attacker with valid
credentials could possibly use this issue to authenticate using
another username, bypassing access control restrictions.
(CVE-2019-0217)

Bernhard Lorenz discovered that the Apache HTTP Server was
inconsistent when processing requests containing multiple consecutive
slashes. This could lead to directives such as LocationMatch and
RewriteRule to perform contrary to expectations. (CVE-2019-0220).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3937-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-bin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");
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
if (! ereg(pattern:"^(14\.04|16\.04|18\.04|18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04 / 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"apache2-bin", pkgver:"2.4.7-1ubuntu4.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"apache2-bin", pkgver:"2.4.18-2ubuntu3.10")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"apache2-bin", pkgver:"2.4.29-1ubuntu4.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"apache2-bin", pkgver:"2.4.34-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-bin");
}
