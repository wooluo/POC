#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4008-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125767);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/07  9:45:01");

  script_cve_id("CVE-2019-11190", "CVE-2019-11191", "CVE-2019-11810", "CVE-2019-11815");
  script_xref(name:"USN", value:"4008-2");

  script_name(english:"Ubuntu 16.04 LTS : apparmor update (USN-4008-2)");
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
"USN-4008-1 fixed multiple security issues in the Linux kernel. This
update provides the corresponding changes to AppArmor policy for
correctly operating under the Linux kernel with fixes for
CVE-2019-11190. Without these changes, some profile transitions may be
unintentionally denied due to missing mmap ('m') rules.

Original advisory details :

Robert Swiecki discovered that the Linux kernel did not properly
apply Address Space Layout Randomization (ASLR) in some situations for
setuid elf binaries. A local attacker could use this to improve the
chances of exploiting an existing vulnerability in a setuid elf
binary. (CVE-2019-11190)

It was discovered that a NULL pointer dereference
vulnerability existed in the LSI Logic MegaRAID driver in
the Linux kernel. A local attacker could use this to cause a
denial of service (system crash). (CVE-2019-11810)

It was discovered that a race condition leading to a
use-after-free existed in the Reliable Datagram Sockets
(RDS) protocol implementation in the Linux kernel. The RDS
protocol is blacklisted by default in Ubuntu. If enabled, a
local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code.
(CVE-2019-11815)

Federico Manuel Bento discovered that the Linux kernel did
not properly apply Address Space Layout Randomization (ASLR)
in some situations for setuid a.out binaries. A local
attacker could use this to improve the chances of exploiting
an existing vulnerability in a setuid a.out binary.
(CVE-2019-11191)

As a hardening measure, this update disables a.out support.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4008-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected apparmor-profiles and / or python3-apparmor
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apparmor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");
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
if (! ereg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"apparmor-profiles", pkgver:"2.10.95-0ubuntu2.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3-apparmor", pkgver:"2.10.95-0ubuntu2.11")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apparmor-profiles / python3-apparmor");
}
