#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3930-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123677);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/19 10:37:09");

  script_cve_id("CVE-2018-19824", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8956", "CVE-2019-8980", "CVE-2019-9003", "CVE-2019-9162", "CVE-2019-9213");
  script_xref(name:"USN", value:"3930-2");

  script_name(english:"Ubuntu 18.04 LTS : linux-hwe, linux-azure vulnerabilities (USN-3930-2)");
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
"USN-3930-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.10.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 18.10 for Ubuntu 18.04 LTS.

Mathias Payer and Hui Peng discovered a use-after-free vulnerability
in the Advanced Linux Sound Architecture (ALSA) subsystem. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2018-19824)

Shlomi Oberman, Yuli Shapiro, and Ran Menscher discovered an
information leak in the Bluetooth implementation of the Linux kernel.
An attacker within Bluetooth range could use this to expose sensitive
information (kernel memory). (CVE-2019-3459, CVE-2019-3460)

Jann Horn discovered that the KVM implementation in the Linux kernel
contained a use-after-free vulnerability. An attacker in a guest VM
with access to /dev/kvm could use this to cause a denial of service
(guest VM crash). (CVE-2019-6974)

Jim Mattson and Felix Wilhelm discovered a use-after-free
vulnerability in the KVM subsystem of the Linux kernel, when using
nested virtual machines. A local attacker in a guest VM could use this
to cause a denial of service (system crash) or possibly execute
arbitrary code in the host system. (CVE-2019-7221)

Felix Wilhelm discovered that an information leak vulnerability
existed in the KVM subsystem of the Linux kernel, when nested
virtualization is used. A local attacker could use this to expose
sensitive information (host system memory to a guest VM).
(CVE-2019-7222)

Jann Horn discovered that the eBPF implementation in the Linux kernel
was insufficiently hardened against Spectre V1 attacks. A local
attacker could use this to expose sensitive information.
(CVE-2019-7308)

It was discovered that a use-after-free vulnerability existed in the
user- space API for crypto (af_alg) implementation in the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-8912)

Jakub Jirasek discovered a use-after-free vulnerability in the SCTP
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-8956)

It was discovered that the Linux kernel did not properly deallocate
memory when handling certain errors while reading files. A local
attacker could use this to cause a denial of service (excessive memory
consumption). (CVE-2019-8980)

It was discovered that a use-after-free vulnerability existed in the
IPMI implementation in the Linux kernel. A local attacker with access
to the IPMI character device files could use this to cause a denial of
service (system crash). (CVE-2019-9003)

Jann Horn discovered that the SNMP NAT implementation in the Linux
kernel performed insufficient ASN.1 length checks. An attacker could
use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-9162)

Jann Horn discovered that the mmap implementation in the Linux kernel
did not properly check for the mmap minimum address in some
situations. A local attacker could use this to assist exploiting a
kernel NULL pointer dereference vulnerability. (CVE-2019-9213).

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3930-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/03");
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
if (! ereg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-19824", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8956", "CVE-2019-8980", "CVE-2019-9003", "CVE-2019-9162", "CVE-2019-9213");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3930-2");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.18.0-1014-azure", pkgver:"4.18.0-1014.14~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.18.0-17-generic", pkgver:"4.18.0-17.18~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.18.0-17-generic-lpae", pkgver:"4.18.0-17.18~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.18.0-17-lowlatency", pkgver:"4.18.0-17.18~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.18.0-17-snapdragon", pkgver:"4.18.0-17.18~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"4.18.0.1014.13")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"4.18.0.17.67")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"4.18.0.17.67")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"4.18.0.17.67")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"4.18.0.17.67")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"4.18.0.17.67")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.18-azure / linux-image-4.18-generic / etc");
}
