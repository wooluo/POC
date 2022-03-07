#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3935-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123751);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/18 10:31:32");

  script_cve_id("CVE-2011-5325", "CVE-2014-9645", "CVE-2015-9261", "CVE-2016-2147", "CVE-2016-2148", "CVE-2017-15873", "CVE-2017-16544", "CVE-2018-1000517", "CVE-2018-20679", "CVE-2019-5747");
  script_xref(name:"USN", value:"3935-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 18.10 : busybox vulnerabilities (USN-3935-1)");
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
"Tyler Hicks discovered that BusyBox incorrectly handled symlinks
inside tar archives. If a user or automated system were tricked into
processing a specially crafted tar archive, a remote attacker could
overwrite arbitrary files outside of the current directory. This issue
only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2011-5325)

Mathias Krause discovered that BusyBox incorrectly handled kernel
module loading restrictions. A local attacker could possibly use this
issue to bypass intended restrictions. This issue only affected Ubuntu
14.04 LTS. (CVE-2014-9645)

It was discovered that BusyBox incorrectly handled certain ZIP
archives. If a user or automated system were tricked into processing a
specially crafted ZIP archive, a remote attacker could cause BusyBox
to crash, leading to a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2015-9261)

Nico Golde discovered that the BusyBox DHCP client incorrectly handled
certain malformed domain names. A remote attacker could possibly use
this issue to cause the DHCP client to crash, leading to a denial of
service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04
LTS. (CVE-2016-2147)

Nico Golde discovered that the BusyBox DHCP client incorrectly handled
certain 6RD options. A remote attacker could use this issue to cause
the DHCP client to crash, leading to a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-2148)

It was discovered that BusyBox incorrectly handled certain bzip2
archives. If a user or automated system were tricked into processing a
specially crafted bzip2 archive, a remote attacker could cause BusyBox
to crash, leading to a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2017-15873)

It was discovered that BusyBox incorrectly handled tab completion. A
local attacker could possibly use this issue to execute arbitrary
code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2017-16544)

It was discovered that the BusyBox wget utility incorrectly handled
certain responses. A remote attacker could use this issue to cause
BusyBox to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2018-1000517)

It was discovered that the BusyBox DHCP utilities incorrectly handled
certain memory operations. A remote attacker could possibly use this
issue to access sensitive information. (CVE-2018-20679, CVE-2019-5747).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3935-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:busybox-initramfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:busybox-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udhcpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udhcpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/04");
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

if (ubuntu_check(osver:"14.04", pkgname:"busybox", pkgver:"1:1.21.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"busybox-initramfs", pkgver:"1:1.21.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"busybox-static", pkgver:"1:1.21.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"udhcpc", pkgver:"1:1.21.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"udhcpd", pkgver:"1:1.21.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"busybox", pkgver:"1:1.22.0-15ubuntu1.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"busybox-initramfs", pkgver:"1:1.22.0-15ubuntu1.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"busybox-static", pkgver:"1:1.22.0-15ubuntu1.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"udhcpc", pkgver:"1:1.22.0-15ubuntu1.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"udhcpd", pkgver:"1:1.22.0-15ubuntu1.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"busybox", pkgver:"1:1.27.2-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"busybox-initramfs", pkgver:"1:1.27.2-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"busybox-static", pkgver:"1:1.27.2-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"udhcpc", pkgver:"1:1.27.2-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"udhcpd", pkgver:"1:1.27.2-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"busybox", pkgver:"1:1.27.2-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"busybox-initramfs", pkgver:"1:1.27.2-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"busybox-static", pkgver:"1:1.27.2-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"udhcpc", pkgver:"1:1.27.2-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"udhcpd", pkgver:"1:1.27.2-2ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "busybox / busybox-initramfs / busybox-static / udhcpc / udhcpd");
}
