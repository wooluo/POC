#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3991-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125948);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/26 16:46:13");

  script_cve_id("CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11695", "CVE-2019-11696", "CVE-2019-11697", "CVE-2019-11698", "CVE-2019-11699", "CVE-2019-11701", "CVE-2019-7317", "CVE-2019-9800", "CVE-2019-9814", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-9821");
  script_xref(name:"USN", value:"3991-3");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : firefox regression (USN-3991-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-3991-1 fixed vulnerabilities in Firefox, and USN-3991-2 fixed a
subsequent regression. The update caused an additional regression that
resulted in Firefox failing to load correctly after executing it in
safe mode. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details :

Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, spoof the
browser UI, trick the user in to launching local executable binaries,
obtain sensitive information, conduct cross-site scripting (XSS)
attacks, or execute arbitrary code. (CVE-2019-11691, CVE-2019-11692,
CVE-2019-11693, CVE-2019-11695, CVE-2019-11696, CVE-2019-11699,
CVE-2019-11701, CVE-2019-7317, CVE-2019-9800, CVE-2019-9814,
CVE-2019-9817, CVE-2019-9819, CVE-2019-9820, CVE-2019-9821)

It was discovered that pressing certain key combinations
could bypass addon installation prompt delays. If a user
opened a specially crafted website, an attacker could
potentially exploit this to trick them in to installing a
malicious extension. (CVE-2019-11697)

It was discovered that history data could be exposed via
drag and drop of hyperlinks to and from bookmarks. If a user
were tricked in to dragging a specially crafted hyperlink to
the bookmark toolbar or sidebar, and subsequently back in to
the web content area, an attacker could potentially exploit
this to obtain sensitive information. (CVE-2019-11698)

A type confusion bug was discovered with object groups and
UnboxedObjects. If a user were tricked in to opening a
specially crafted website after enabling the UnboxedObjects
feature, an attacker could potentially exploit this to
bypass security checks. (CVE-2019-9816).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3991-3/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/17");
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

if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"67.0.2+build2-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"firefox", pkgver:"67.0.2+build2-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"firefox", pkgver:"67.0.2+build2-0ubuntu0.18.10.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"firefox", pkgver:"67.0.2+build2-0ubuntu0.19.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
