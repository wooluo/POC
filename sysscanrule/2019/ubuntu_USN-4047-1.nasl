#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4047-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126563);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-10161", "CVE-2019-10166", "CVE-2019-10167", "CVE-2019-10168");
  script_xref(name:"USN", value:"4047-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : libvirt vulnerabilities (USN-4047-1)");
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
"Matthias Gerstner and Jan Tomko discovered that libvirt incorrectly
handled certain API calls. An attacker could possibly use this issue
to check for arbitrary files, or execute arbitrary binaries. In the
default installation, attackers would be isolated by the libvirt
AppArmor profile.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4047-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");
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

if (ubuntu_check(osver:"16.04", pkgname:"libvirt-bin", pkgver:"1.3.1-1ubuntu10.27")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libvirt0", pkgver:"1.3.1-1ubuntu10.27")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvirt-clients", pkgver:"4.0.0-1ubuntu8.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvirt-daemon", pkgver:"4.0.0-1ubuntu8.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvirt0", pkgver:"4.0.0-1ubuntu8.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libvirt-clients", pkgver:"4.6.0-2ubuntu3.8")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libvirt-daemon", pkgver:"4.6.0-2ubuntu3.8")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libvirt0", pkgver:"4.6.0-2ubuntu3.8")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libvirt-clients", pkgver:"5.0.0-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libvirt-daemon", pkgver:"5.0.0-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libvirt0", pkgver:"5.0.0-1ubuntu2.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt-bin / libvirt-clients / libvirt-daemon / libvirt0");
}
