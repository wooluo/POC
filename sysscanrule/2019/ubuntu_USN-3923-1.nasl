#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3923-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123457);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/28 10:07:14");

  script_cve_id("CVE-2018-16867", "CVE-2018-16872", "CVE-2018-19489", "CVE-2018-20123", "CVE-2018-20124", "CVE-2018-20125", "CVE-2018-20126", "CVE-2018-20191", "CVE-2018-20216", "CVE-2019-3812", "CVE-2019-6778");
  script_xref(name:"USN", value:"3923-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 18.10 : qemu vulnerabilities (USN-3923-1)");
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
"Michael Hanselmann discovered that QEMU incorrectly handled the Media
Transfer Protocol (MTP). An attacker inside the guest could use this
issue to read or write arbitrary files and cause a denial of service,
or possibly execute arbitrary code. This issue only affected Ubuntu
18.10. (CVE-2018-16867)

Michael Hanselmann discovered that QEMU incorrectly handled the Media
Transfer Protocol (MTP). An attacker inside the guest could use this
issue to read arbitrary files, contrary to expectations. This issue
only affected Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-16872)

Zhibin Hu discovered that QEMU incorrectly handled the Plan 9 File
System support. An attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service.
(CVE-2018-19489)

Li Quang and Saar Amar discovered multiple issues in the QEMU PVRDMA
device. An attacker inside the guest could use these issues to cause a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.10. These issues were resolved by disabling PVRDMA
support in Ubuntu 18.10. (CVE-2018-20123, CVE-2018-20124,
CVE-2018-20125, CVE-2018-20126, CVE-2018-20191, CVE-2018-20216)

Michael Hanselmann discovered that QEMU incorrectly handled certain
i2c commands. A local attacker could possibly use this issue to read
QEMU process memory. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 18.10. (CVE-2019-3812)

It was discovered that QEMU incorrectly handled the Slirp networking
back-end. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service, or possibly execute
arbitrary code on the host. In the default installation, when QEMU is
used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2019-6778).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3923-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/28");
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

if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.45")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-arm", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-mips", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-misc", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-ppc", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-s390x", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-sparc", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.36")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-arm", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-mips", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-misc", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-ppc", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-s390x", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-sparc", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-x86", pkgver:"1:2.11+dfsg-1ubuntu7.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-arm", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-data", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-gui", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-mips", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-misc", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-ppc", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-s390x", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-sparc", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-x86", pkgver:"1:2.12+dfsg-3ubuntu8.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-system / qemu-system-aarch64 / qemu-system-arm / etc");
}
