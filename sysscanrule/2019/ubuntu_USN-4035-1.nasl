#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4035-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126255);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/26 10:34:06");

  script_cve_id("CVE-2018-14662", "CVE-2018-16846", "CVE-2018-16889", "CVE-2019-3821");
  script_xref(name:"USN", value:"4035-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.10 / 19.04 : ceph vulnerabilities (USN-4035-1)");
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
"It was discovered that Ceph incorrectly handled read only permissions.
An authenticated attacker could use this issue to obtain dm-crypt
encryption keys. This issue only affected Ubuntu 16.04 LTS.
(CVE-2018-14662)

It was discovered that Ceph incorrectly handled certain OMAPs holding
bucket indices. An authenticated attacker could possibly use this
issue to cause a denial of service. This issue only affected Ubuntu
16.04 LTS. (CVE-2018-16846)

It was discovered that Ceph incorrectly sanitized certain debug logs.
A local attacker could possibly use this issue to obtain encryption
key information. This issue was only addressed in Ubuntu 18.10 and
Ubuntu 19.04. (CVE-2018-16889)

It was discovered that Ceph incorrectly handled certain civetweb
requests. A remote attacker could possibly use this issue to consume
resources, leading to a denial of service. This issue only affected
Ubuntu 18.10 and Ubuntu 19.04. (CVE-2019-3821).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4035-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ceph and / or ceph-common packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
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
if (! ereg(pattern:"^(16\.04|18\.10|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.10 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"ceph", pkgver:"10.2.11-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ceph-common", pkgver:"10.2.11-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"ceph", pkgver:"13.2.4+dfsg1-0ubuntu0.18.10.2")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"ceph-common", pkgver:"13.2.4+dfsg1-0ubuntu0.18.10.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"ceph", pkgver:"13.2.4+dfsg1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"ceph-common", pkgver:"13.2.4+dfsg1-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph / ceph-common");
}
