#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3986-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125252);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/17  9:44:15");

  script_cve_id("CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903", "CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214");
  script_xref(name:"USN", value:"3986-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 : Wireshark vulnerabilities (USN-3986-1)");
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
"It was discovered that Wireshark improperly handled certain input. A
remote or local attacker could cause Wireshark to crash by injecting
malformed packets onto the wire or convincing someone to read a
malformed packet trace file.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3986-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwireshark11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwiretap8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwscodecs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwsutil9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");
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
if (! ereg(pattern:"^(16\.04|18\.04|18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"libwireshark-data", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libwireshark11", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libwiretap8", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libwscodecs2", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libwsutil9", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"tshark", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"wireshark", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"wireshark-common", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"wireshark-gtk", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"wireshark-qt", pkgver:"2.6.8-1~ubuntu16.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libwireshark-data", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libwireshark11", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libwiretap8", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libwscodecs2", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libwsutil9", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"tshark", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"wireshark", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"wireshark-common", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"wireshark-gtk", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"wireshark-qt", pkgver:"2.6.8-1~ubuntu18.04.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libwireshark-data", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libwireshark11", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libwiretap8", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libwscodecs2", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libwsutil9", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"tshark", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"wireshark", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"wireshark-common", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"wireshark-gtk", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"wireshark-qt", pkgver:"2.6.8-1~ubuntu18.10.0")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwireshark-data / libwireshark11 / libwiretap8 / libwscodecs2 / etc");
}
