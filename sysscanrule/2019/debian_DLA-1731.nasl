#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1731-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123420);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2016-10741", "CVE-2017-13305", "CVE-2017-5753", "CVE-2018-12896", "CVE-2018-13053", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-20511", "CVE-2018-3639", "CVE-2018-5848", "CVE-2018-5953", "CVE-2019-3701", "CVE-2019-3819", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-9213");

  script_name(english:"Debian DLA-1731-2 : linux regression update (Spectre)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The linux update issued as DLA-1731-1 caused a regression in the
vmxnet3 (VMware virtual network adapter) driver. This update corrects
that regression, and an earlier regression in the CIFS network
filesystem implementation introduced in DLA-1422-1. For reference the
original advisory text follows.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2016-10741

A race condition was discovered in XFS that would result in a crash
(BUG). A local user permitted to write to an XFS volume could use this
for denial of service.

CVE-2017-5753

Further instances of code that was vulnerable to Spectre variant 1
(bounds-check bypass) have been mitigated.

CVE-2017-13305

A memory over-read was discovered in the keys subsystem's encrypted
key type. A local user could use this for denial of service or
possibly to read sensitive information.

CVE-2018-3639 (SSB)

Multiple researchers have discovered that Speculative Store Bypass
(SSB), a feature implemented in many processors, could be used to read
sensitive information from another context. In particular, code in a
software sandbox may be able to read sensitive information from
outside the sandbox. This issue is also known as Spectre variant 4.

This update fixes bugs in the mitigations for SSB for AMD
processors.

CVE-2018-5848

The wil6210 wifi driver did not properly validate lengths in scan and
connection requests, leading to a possible buffer overflow. On systems
using this driver, a local user with the CAP_NET_ADMIN capability
could use this for denial of service (memory corruption or crash) or
potentially for privilege escalation.

CVE-2018-5953

The swiotlb subsystem printed kernel memory addresses to the system
log, which could help a local attacker to exploit other
vulnerabilities.

CVE-2018-12896, CVE-2018-13053

Team OWL337 reported possible integer overflows in the POSIX timer
implementation. These might have some security impact.

CVE-2018-16862

Vasily Averin and Pavel Tikhomirov from Virtuozzo Kernel Team
discovered that the cleancache memory management feature did not
invalidate cached data for deleted files. On Xen guests using the tmem
driver, local users could potentially read data from other users'
deleted files if they were able to create new files on the same
volume.

CVE-2018-16884

A flaw was found in the NFS 4.1 client implementation. Mounting NFS
shares in multiple network namespaces at the same time could lead to a
user-after-free. Local users might be able to use this for denial of
service (memory corruption or crash) or possibly for privilege
escalation.

This can be mitigated by disabling unprivileged users from
creating user namespaces, which is the default in Debian.

CVE-2018-17972

Jann Horn reported that the /proc/*/stack files in procfs leaked
sensitive data from the kernel. These files are now only readable by
users with the CAP_SYS_ADMIN capability (usually only root)

CVE-2018-18281

Jann Horn reported a race condition in the virtual memory manager that
can result in a process briefly having access to memory after it is
freed and reallocated. A local user permitted to create containers
could possibly exploit this for denial of service (memory corruption)
or for privilege escalation.

CVE-2018-18690

Kanda Motohiro reported that XFS did not correctly handle some xattr
(extended attribute) writes that require changing the disk format of
the xattr. A user with access to an XFS volume could use this for
denial of service.

CVE-2018-18710

It was discovered that the cdrom driver does not correctly validate
the parameter to the CDROM_SELECT_DISC ioctl. A user with access to a
cdrom device could use this to read sensitive information from the
kernel or to cause a denial of service (crash).

CVE-2018-19824

Hui Peng and Mathias Payer discovered a use-after-free bug in the USB
audio driver. A physically present attacker able to attach a specially
designed USB device could use this for privilege escalation.

CVE-2018-19985

Hui Peng and Mathias Payer discovered a missing bounds check in the
hso USB serial driver. A physically present user able to attach a
specially designed USB device could use this to read sensitive
information from the kernel or to cause a denial of service (crash).

CVE-2018-20169

Hui Peng and Mathias Payer discovered missing bounds checks in the USB
core. A physically present attacker able to attach a specially
designed USB device could use this to cause a denial of service
(crash) or possibly for privilege escalation.

CVE-2018-20511

InfoSect reported an information leak in the AppleTalk IP/DDP
implemntation. A local user with CAP_NET_ADMIN capability could use
this to read sensitive information from the kernel.

CVE-2019-3701

Muyu Yu and Marcus Meissner reported that the CAN gateway
implementation allowed the frame length to be modified, typically
resulting in out-of-bounds memory-mapped I/O writes. On a system with
CAN devices present, a local user with CAP_NET_ADMIN capability in the
initial net namespace could use this to cause a crash (oops) or other
hardware-dependent impact.

CVE-2019-3819

A potential infinite loop was discovered in the HID debugfs interface
exposed under /sys/kernel/debug/hid. A user with access to these files
could use this for denial of service.

This interface is only accessible to root by default, which
fully mitigates the issue.

CVE-2019-6974

Jann Horn reported a use-after-free bug in KVM. A local user with
access to /dev/kvm could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

CVE-2019-7221

Jim Mattson and Felix Wilhelm reported a user-after-free bug in KVM's
nested VMX implementation. On systems with Intel CPUs, a local user
with access to /dev/kvm could use this to cause a denial of service
(memory corruption or crash) or possibly for privilege escalation.

Nested VMX is disabled by default, which fully mitigates the
issue.

CVE-2019-7222

Felix Wilhelm reported an information leak in KVM for x86. A local
user with access to /dev/kvm could use this to read sensitive
information from the kernel.

CVE-2019-9213

Jann Horn reported that privileged tasks could cause stack segments,
including those in other processes, to grow downward to address 0. On
systems lacking SMAP (x86) or PAN (ARM), this exacerbated other
vulnerabilities: a NULL pointer dereference could be exploited for
privilege escalation rather than only for denial of service.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.64-1.

We recommend that you upgrade your linux packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/04/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.9-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-3.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-586");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-ixp4xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-kirkwood");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-orion5x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-586");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-ixp4xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-kirkwood");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-orion5x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-3.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-3.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-3.16.0-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-3.16.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.64-2")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.64-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
