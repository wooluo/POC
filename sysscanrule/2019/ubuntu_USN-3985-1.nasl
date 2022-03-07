#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3985-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125215);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/16 10:38:53");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_xref(name:"USN", value:"3985-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : libvirt update (USN-3985-1) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
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
"Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Giorgi
Maisuradze, Dan Horea Lutas, Andrei Lutas, Volodymyr Pikhur, Stephan
van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh
Razavi, Herbert Bos, Cristiano Giuffrida, Moritz Lipp, Michael
Schwarz, and Daniel Gruss discovered that memory previously stored in
microarchitectural fill buffers of an Intel CPU core may be exposed to
a malicious process that is executing on the same CPU core. A local
attacker could use this to expose sensitive information.
(CVE-2018-12130)

Brandon Falk, Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco,
Stephan van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro
Frigo, Kaveh Razavi, Herbert Bos, and Cristiano Giuffrida discovered
that memory previously stored in microarchitectural load ports of an
Intel CPU core may be exposed to a malicious process that is executing
on the same CPU core. A local attacker could use this to expose
sensitive information. (CVE-2018-12127)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Marina Minkin,
Daniel Moghimi, Moritz Lipp, Michael Schwarz, Jo Van Bulck, Daniel
Genkin, Daniel Gruss, Berk Sunar, Frank Piessens, and Yuval Yarom
discovered that memory previously stored in microarchitectural store
buffers of an Intel CPU core may be exposed to a malicious process
that is executing on the same CPU core. A local attacker could use
this to expose sensitive information. (CVE-2018-12126)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Volodrmyr Pikhur,
Moritz Lipp, Michael Schwarz, Daniel Gruss, Stephan van Schaik, Alyssa
Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh Razavi, Herbert
Bos, and Cristiano Giuffrida discovered that uncacheable memory
previously stored in microarchitectural buffers of an Intel CPU core
may be exposed to a malicious process that is executing on the same
CPU core. A local attacker could use this to expose sensitive
information. (CVE-2019-11091).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3985-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if (ubuntu_check(osver:"16.04", pkgname:"libvirt-bin", pkgver:"1.3.1-1ubuntu10.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libvirt0", pkgver:"1.3.1-1ubuntu10.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvirt-clients", pkgver:"4.0.0-1ubuntu8.10")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvirt-daemon", pkgver:"4.0.0-1ubuntu8.10")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvirt0", pkgver:"4.0.0-1ubuntu8.10")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libvirt-clients", pkgver:"4.6.0-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libvirt-daemon", pkgver:"4.6.0-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libvirt0", pkgver:"4.6.0-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libvirt-clients", pkgver:"5.0.0-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libvirt-daemon", pkgver:"5.0.0-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libvirt0", pkgver:"5.0.0-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt-bin / libvirt-clients / libvirt-daemon / libvirt0");
}
