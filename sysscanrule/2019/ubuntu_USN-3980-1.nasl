#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3980-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125139);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/15  9:53:42");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16884", "CVE-2019-11091", "CVE-2019-3874", "CVE-2019-3882", "CVE-2019-3887", "CVE-2019-9500", "CVE-2019-9503");
  script_xref(name:"USN", value:"3980-1");

  script_name(english:"Ubuntu 18.10 : linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-raspi2 vulnerabilities (USN-3980-1) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
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

Vasily Averin and Evgenii Shatokhin discovered that a use-after-free
vulnerability existed in the NFS41+ subsystem when multiple network
namespaces are in use. A local attacker in a container could use this
to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-16884)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Volodrmyr Pikhur,
Moritz Lipp, Michael Schwarz, Daniel Gruss, Stephan van Schaik, Alyssa
Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh Razavi, Herbert
Bos, and Cristiano Giuffrida discovered that uncacheable memory
previously stored in microarchitectural buffers of an Intel CPU core
may be exposed to a malicious process that is executing on the same
CPU core. A local attacker could use this to expose sensitive
information. (CVE-2019-11091)

Matteo Croce, Natale Vinto, and Andrea Spagnolo discovered that the
cgroups subsystem of the Linux kernel did not properly account for
SCTP socket buffers. A local attacker could use this to cause a denial
of service (system crash). (CVE-2019-3874)

Alex Williamson discovered that the vfio subsystem of the Linux kernel
did not properly limit DMA mappings. A local attacker could use this
to cause a denial of service (memory exhaustion). (CVE-2019-3882)

Marc Orr discovered that the KVM hypervisor implementation in the
Linux kernel did not properly restrict APIC MSR register values when
nested virtualization is used. An attacker in a guest vm could use
this to cause a denial of service (host OS crash). (CVE-2019-3887)

Hugues Anguelkov discovered that the Broadcom Wifi driver in the Linux
kernel contained a head puffer overflow. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2019-9500)

Hugues Anguelkov discovered that the Broadcom Wifi driver in the Linux
kernel did not properly prevent remote firmware events from being
processed for USB Wifi devices. A physically proximate attacker could
use this to send firmware events to the device. (CVE-2019-9503).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3980-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019 Canonical, Inc. / NASL script (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16884", "CVE-2019-11091", "CVE-2019-3874", "CVE-2019-3882", "CVE-2019-3887", "CVE-2019-9500", "CVE-2019-9503");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3980-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1011-gcp", pkgver:"4.18.0-1011.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1012-kvm", pkgver:"4.18.0-1012.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1014-raspi2", pkgver:"4.18.0-1014.16")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1016-aws", pkgver:"4.18.0-1016.18")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1018-azure", pkgver:"4.18.0-1018.18")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-20-generic", pkgver:"4.18.0-20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-20-generic-lpae", pkgver:"4.18.0-20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-20-lowlatency", pkgver:"4.18.0-20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-20-snapdragon", pkgver:"4.18.0-20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-aws", pkgver:"4.18.0.1016.16")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-azure", pkgver:"4.18.0.1018.19")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-gcp", pkgver:"4.18.0.1011.11")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-generic", pkgver:"4.18.0.20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-generic-lpae", pkgver:"4.18.0.20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-gke", pkgver:"4.18.0.1011.11")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-kvm", pkgver:"4.18.0.1012.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-lowlatency", pkgver:"4.18.0.20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-raspi2", pkgver:"4.18.0.1014.11")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-snapdragon", pkgver:"4.18.0.20.21")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-virtual", pkgver:"4.18.0.20.21")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.18-aws / linux-image-4.18-azure / etc");
}
