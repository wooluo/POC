#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3993-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125355);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/30 11:03:54");

  script_cve_id("CVE-2019-5435", "CVE-2019-5436");
  script_xref(name:"USN", value:"3993-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : curl vulnerabilities (USN-3993-1)");
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
"Wenchao Li discovered that curl incorrectly handled memory in the
curl_url_set() function. A remote attacker could use this issue to
cause curl to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 19.04.
(CVE-2019-5435)

It was discovered that curl incorrectly handled memory when receiving
data from a TFTP server. A remote attacker could use this issue to
cause curl to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2019-5436).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3993-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");
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

if (ubuntu_check(osver:"16.04", pkgname:"curl", pkgver:"7.47.0-1ubuntu2.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3", pkgver:"7.47.0-1ubuntu2.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-gnutls", pkgver:"7.47.0-1ubuntu2.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-nss", pkgver:"7.47.0-1ubuntu2.13")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"curl", pkgver:"7.58.0-2ubuntu3.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl3-gnutls", pkgver:"7.58.0-2ubuntu3.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl3-nss", pkgver:"7.58.0-2ubuntu3.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libcurl4", pkgver:"7.58.0-2ubuntu3.7")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"curl", pkgver:"7.61.0-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libcurl3-gnutls", pkgver:"7.61.0-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libcurl3-nss", pkgver:"7.61.0-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libcurl4", pkgver:"7.61.0-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"curl", pkgver:"7.64.0-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libcurl3-gnutls", pkgver:"7.64.0-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libcurl3-nss", pkgver:"7.64.0-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libcurl4", pkgver:"7.64.0-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl3 / libcurl3-gnutls / libcurl3-nss / libcurl4");
}