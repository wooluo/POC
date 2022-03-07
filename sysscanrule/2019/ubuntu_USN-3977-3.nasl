#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3977-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126095);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/21 12:43:07");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_xref(name:"USN", value:"3977-3");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 / 19.04 : intel-microcode update (USN-3977-3) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-3977-1 and USN-3977-2 provided mitigations for Microarchitectural
Data Sampling (MDS) vulnerabilities in Intel Microcode for a large
number of Intel processor families. This update provides the
corresponding updated microcode mitigations for the Intel Sandy Bridge
processor family

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Giorgi
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
    value:"https://usn.ubuntu.com/3977-3/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected intel-microcode package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:intel-microcode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");
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
if (! ereg(pattern:"^(14\.04|16\.04|18\.04|18\.10|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04 / 18.10 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"intel-microcode", pkgver:"3.20190618.0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"intel-microcode", pkgver:"3.20190618.0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"intel-microcode", pkgver:"3.20190618.0ubuntu0.18.10.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"intel-microcode", pkgver:"3.20190618.0ubuntu0.19.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "intel-microcode");
}
