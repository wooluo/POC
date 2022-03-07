#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4094-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127889);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/14 10:36:48");

  script_cve_id("CVE-2018-13053", "CVE-2018-13093", "CVE-2018-13096", "CVE-2018-13097", "CVE-2018-13098", "CVE-2018-13099", "CVE-2018-13100", "CVE-2018-14609", "CVE-2018-14610", "CVE-2018-14611", "CVE-2018-14612", "CVE-2018-14613", "CVE-2018-14614", "CVE-2018-14615", "CVE-2018-14616", "CVE-2018-14617", "CVE-2018-16862", "CVE-2018-20169", "CVE-2018-20511", "CVE-2018-20856", "CVE-2018-5383", "CVE-2019-10126", "CVE-2019-1125", "CVE-2019-12614", "CVE-2019-12818", "CVE-2019-12819", "CVE-2019-12984", "CVE-2019-13233", "CVE-2019-13272", "CVE-2019-2024", "CVE-2019-2101", "CVE-2019-3846");
  script_xref(name:"USN", value:"4094-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : linux, linux-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-kvm, (USN-4094-1)");
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
"It was discovered that the alarmtimer implementation in the Linux
kernel contained an integer overflow vulnerability. A local attacker
could use this to cause a denial of service. (CVE-2018-13053)

Wen Xu discovered that the XFS filesystem implementation in the Linux
kernel did not properly track inode validations. An attacker could use
this to construct a malicious XFS image that, when mounted, could
cause a denial of service (system crash). (CVE-2018-13093)

Wen Xu discovered that the f2fs file system implementation in the
Linux kernel did not properly validate metadata. An attacker could use
this to construct a malicious f2fs image that, when mounted, could
cause a denial of service (system crash). (CVE-2018-13097,
CVE-2018-13099, CVE-2018-13100, CVE-2018-14614, CVE-2018-14616,
CVE-2018-13096, CVE-2018-13098, CVE-2018-14615)

Wen Xu and Po-Ning Tseng discovered that btrfs file system
implementation in the Linux kernel did not properly validate metadata.
An attacker could use this to construct a malicious btrfs image that,
when mounted, could cause a denial of service (system crash).
(CVE-2018-14610, CVE-2018-14611, CVE-2018-14612, CVE-2018-14613,
CVE-2018-14609)

Wen Xu discovered that the HFS+ filesystem implementation in the Linux
kernel did not properly handle malformed catalog data in some
situations. An attacker could use this to construct a malicious HFS+
image that, when mounted, could cause a denial of service (system
crash). (CVE-2018-14617)

Vasily Averin and Pavel Tikhomirov discovered that the cleancache
subsystem of the Linux kernel did not properly initialize new files in
some situations. A local attacker could use this to expose sensitive
information. (CVE-2018-16862)

Hui Peng and Mathias Payer discovered that the USB subsystem in the
Linux kernel did not properly handle size checks when handling an
extra USB descriptor. A physically proximate attacker could use this
to cause a denial of service (system crash). (CVE-2018-20169)

It was discovered that a use-after-free error existed in the block
layer subsystem of the Linux kernel when certain failure conditions
occurred. A local attacker could possibly use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2018-20856)

Eli Biham and Lior Neumann discovered that the Bluetooth
implementation in the Linux kernel did not properly validate elliptic
curve parameters during Diffie-Hellman key exchange in some
situations. An attacker could use this to expose sensitive
information. (CVE-2018-5383)

It was discovered that a heap buffer overflow existed in the Marvell
Wireless LAN device driver for the Linux kernel. An attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-10126)

Andrei Vlad Lutas and Dan Lutas discovered that some x86 processors
incorrectly handle SWAPGS instructions during speculative execution. A
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2019-1125)

It was discovered that the PowerPC dlpar implementation in the Linux
kernel did not properly check for allocation errors in some
situations. A local attacker could possibly use this to cause a denial
of service (system crash). (CVE-2019-12614)

It was discovered that a NULL pointer dereference vulnerabilty existed
in the Near-field communication (NFC) implementation in the Linux
kernel. An attacker could use this to cause a denial of service
(system crash). (CVE-2019-12818)

It was discovered that the MDIO bus devices subsystem in the Linux
kernel improperly dropped a device reference in an error condition,
leading to a use-after-free. An attacker could use this to cause a
denial of service (system crash). (CVE-2019-12819)

It was discovered that a NULL pointer dereference vulnerability
existed in the Near-field communication (NFC) implementation in the
Linux kernel. A local attacker could use this to cause a denial of
service (system crash). (CVE-2019-12984)

Jann Horn discovered a use-after-free vulnerability in the Linux
kernel when accessing LDT entries in some situations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-13233)

Jann Horn discovered that the ptrace implementation in the Linux
kernel did not properly record credentials in some situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly gain administrative privileges. (CVE-2019-13272)

It was discovered that the Empia EM28xx DVB USB device driver
implementation in the Linux kernel contained a use-after-free
vulnerability when disconnecting the device. An attacker could use
this to cause a denial of service (system crash). (CVE-2019-2024)

It was discovered that the USB video device class implementation in
the Linux kernel did not properly validate control bits, resulting in
an out of bounds buffer read. A local attacker could use this to
possibly expose sensitive information (kernel memory). (CVE-2019-2101)

It was discovered that the Marvell Wireless LAN device driver in the
Linux kernel did not properly validate the BSS descriptor. A local
attacker could possibly use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2019-3846)

It was discovered that the Appletalk IP encapsulation driver in the
Linux kernel did not properly prevent kernel addresses from being
copied to user space. A local attacker with the CAP_NET_ADMIN
capability could use this to expose sensitive information.
(CVE-2018-20511).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4094-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-4.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");
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
if (! ereg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-13053", "CVE-2018-13093", "CVE-2018-13096", "CVE-2018-13097", "CVE-2018-13098", "CVE-2018-13099", "CVE-2018-13100", "CVE-2018-14609", "CVE-2018-14610", "CVE-2018-14611", "CVE-2018-14612", "CVE-2018-14613", "CVE-2018-14614", "CVE-2018-14615", "CVE-2018-14616", "CVE-2018-14617", "CVE-2018-16862", "CVE-2018-20169", "CVE-2018-20511", "CVE-2018-20856", "CVE-2018-5383", "CVE-2019-10126", "CVE-2019-1125", "CVE-2019-12614", "CVE-2019-12818", "CVE-2019-12819", "CVE-2019-12984", "CVE-2019-13233", "CVE-2019-13272", "CVE-2019-2024", "CVE-2019-2101", "CVE-2019-3846");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4094-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1021-oracle", pkgver:"4.15.0-1021.23~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1040-gcp", pkgver:"4.15.0-1040.42~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1055-azure", pkgver:"4.15.0-1055.60")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-58-generic", pkgver:"4.15.0-58.64~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-58-generic-lpae", pkgver:"4.15.0-58.64~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-58-lowlatency", pkgver:"4.15.0-58.64~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-azure", pkgver:"4.15.0.1055.58")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gcp", pkgver:"4.15.0.1040.54")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.15.0.58.79")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae-hwe-16.04", pkgver:"4.15.0.58.79")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1040.54")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.15.0.58.79")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oem", pkgver:"4.15.0.58.79")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oracle", pkgver:"4.15.0.1021.15")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual-hwe-16.04", pkgver:"4.15.0.58.79")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1021-oracle", pkgver:"4.15.0-1021.23")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1040-gcp", pkgver:"4.15.0-1040.42")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1040-gke", pkgver:"4.15.0-1040.42")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1042-kvm", pkgver:"4.15.0-1042.42")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1043-raspi2", pkgver:"4.15.0-1043.46")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1050-oem", pkgver:"4.15.0-1050.57")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1060-snapdragon", pkgver:"4.15.0-1060.66")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-58-generic", pkgver:"4.15.0-58.64")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-58-generic-lpae", pkgver:"4.15.0-58.64")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-58-lowlatency", pkgver:"4.15.0-58.64")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"4.15.0.1040.42")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic", pkgver:"4.15.0.58.60")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae", pkgver:"4.15.0.58.60")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1040.43")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-4.15", pkgver:"4.15.0.1040.43")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-kvm", pkgver:"4.15.0.1042.42")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency", pkgver:"4.15.0.58.60")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem", pkgver:"4.15.0.1050.54")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"4.15.0.1021.24")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2", pkgver:"4.15.0.1043.41")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon", pkgver:"4.15.0.1060.63")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual", pkgver:"4.15.0.58.60")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.15-azure / linux-image-4.15-gcp / etc");
}
