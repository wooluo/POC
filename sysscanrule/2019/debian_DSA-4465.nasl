#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4465. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125959);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2019-10126", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11486", "CVE-2019-11599", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-3846", "CVE-2019-5489", "CVE-2019-9500", "CVE-2019-9503");
  script_xref(name:"DSA", value:"4465");

  script_name(english:"Debian DSA-4465-1 : linux - security update (SACK Panic) (SACK Slowness)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

  - CVE-2019-3846, CVE-2019-10126
    huangwen reported multiple buffer overflows in the
    Marvell wifi (mwifiex) driver, which a local user could
    use to cause denial of service or the execution of
    arbitrary code.

  - CVE-2019-5489
    Daniel Gruss, Erik Kraft, Trishita Tiwari, Michael
    Schwarz, Ari Trachtenberg, Jason Hennessey, Alex
    Ionescu, and Anders Fogh discovered that local users
    could use the mincore() system call to obtain sensitive
    information from other processes that access the same
    memory-mapped file.

  - CVE-2019-9500, CVE-2019-9503
    Hugues Anguelkov discovered a buffer overflow and
    missing access validation in the Broadcom FullMAC wifi
    driver (brcmfmac), which a attacker on the same wifi
    network could use to cause denial of service or the
    execution of arbitrary code.

  - CVE-2019-11477
    Jonathan Looney reported that a specially crafted
    sequence of TCP selective acknowledgements (SACKs)
    allows a remotely triggerable kernel panic.

  - CVE-2019-11478
    Jonathan Looney reported that a specially crafted
    sequence of TCP selective acknowledgements (SACKs) will
    fragment the TCP retransmission queue, allowing an
    attacker to cause excessive resource usage.

  - CVE-2019-11479
    Jonathan Looney reported that an attacker could force
    the Linux kernel to segment its responses into multiple
    TCP segments, each of which contains only 8 bytes of
    data, drastically increasing the bandwidth required to
    deliver the same amount of data.

  This update introduces a new sysctl value to control the minimal MSS
  (net.ipv4.tcp_min_snd_mss), which by default uses the formerly hard
  coded value of 48. We recommend raising this to 536 unless you know
  that your network requires a lower value.

  - CVE-2019-11486
    Jann Horn of Google reported numerous race conditions in
    the Siemens R3964 line discipline. A local user could
    use these to cause unspecified security impact. This
    module has therefore been disabled.

  - CVE-2019-11599
    Jann Horn of Google reported a race condition in the
    core dump implementation which could lead to a
    use-after-free. A local user could use this to read
    sensitive information, to cause a denial of service
    (memory corruption), or for privilege escalation.

  - CVE-2019-11815
    It was discovered that a use-after-free in the Reliable
    Datagram Sockets protocol could result in denial of
    service and potentially privilege escalation. This
    protocol module (rds) is not auto loaded on Debian
    systems, so this issue only affects systems where it is
    explicitly loaded.

  - CVE-2019-11833
    It was discovered that the ext4 filesystem
    implementation writes uninitialised data from kernel
    memory to new extent blocks. A local user able to write
    to an ext4 filesystem and then read the filesystem
    image, for example using a removable drive, might be
    able to use this to obtain sensitive information.

  - CVE-2019-11884
    It was discovered that the Bluetooth HIDP implementation
    did not ensure that new connection names were
    null-terminated. A local user with CAP_NET_ADMIN
    capability might be able to use this to obtain sensitive
    information from the kernel stack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=928989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-3846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4465"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.9.168-1+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/18");
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
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.168-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.168-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
