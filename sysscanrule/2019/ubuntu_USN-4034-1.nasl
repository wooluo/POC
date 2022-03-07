#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4034-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126254);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/28 11:31:59");

  script_cve_id("CVE-2017-12805", "CVE-2017-12806", "CVE-2018-14434", "CVE-2018-15607", "CVE-2018-16323", "CVE-2018-16412", "CVE-2018-16413", "CVE-2018-16644", "CVE-2018-16645", "CVE-2018-17965", "CVE-2018-17966", "CVE-2018-18016", "CVE-2018-18023", "CVE-2018-18024", "CVE-2018-18025", "CVE-2018-18544", "CVE-2018-20467", "CVE-2019-10131", "CVE-2019-10649", "CVE-2019-10650", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11597", "CVE-2019-11598", "CVE-2019-7175", "CVE-2019-7395", "CVE-2019-7396", "CVE-2019-7397", "CVE-2019-7398", "CVE-2019-9956");
  script_xref(name:"USN", value:"4034-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : imagemagick vulnerabilities (USN-4034-1)");
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
"It was discovered that ImageMagick incorrectly handled certain
malformed image files. If a user or automated system using ImageMagick
were tricked into opening a specially crafted image, an attacker could
exploit this to cause a denial of service or possibly execute code
with the privileges of the user invoking the program.

Due to a large number of issues discovered in GhostScript that prevent
it from being used by ImageMagick safely, the update for Ubuntu 18.10
and Ubuntu 19.04 includes a default policy change that disables
support for the Postscript and PDF formats in ImageMagick. This policy
can be overridden if necessary by using an alternate ImageMagick
policy configuration.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4034-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-5v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/26");
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

if (ubuntu_check(osver:"16.04", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu5.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu5.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu5.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu5.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu5.14")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"imagemagick", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagick++-6.q16-7", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagickcore-6.q16-3", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagickcore-6.q16-3-extra", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.7")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"imagemagick", pkgver:"8:6.9.10.8+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"imagemagick-6.q16", pkgver:"8:6.9.10.8+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libmagick++-6.q16-8", pkgver:"8:6.9.10.8+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libmagickcore-6.q16-6", pkgver:"8:6.9.10.8+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libmagickcore-6.q16-6-extra", pkgver:"8:6.9.10.8+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"imagemagick", pkgver:"8:6.9.10.14+dfsg-7ubuntu2.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.9.10.14+dfsg-7ubuntu2.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libmagick++-6.q16-8", pkgver:"8:6.9.10.14+dfsg-7ubuntu2.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libmagickcore-6.q16-6", pkgver:"8:6.9.10.14+dfsg-7ubuntu2.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libmagickcore-6.q16-6-extra", pkgver:"8:6.9.10.14+dfsg-7ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / imagemagick-6.q16 / libmagick++-6.q16-5v5 / etc");
}
