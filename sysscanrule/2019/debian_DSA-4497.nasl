#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4497. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127867);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/21  9:43:47");

  script_cve_id("CVE-2015-8553", "CVE-2017-18509", "CVE-2018-20836", "CVE-2018-20856", "CVE-2018-5995", "CVE-2019-10207", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-1125", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-15239", "CVE-2019-3882", "CVE-2019-3900");
  script_xref(name:"DSA", value:"4497");

  script_name(english:"Debian DSA-4497-1 : linux - security update");
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

  - CVE-2015-8553
    Jan Beulich discovered that CVE-2015-2150 was not
    completely addressed. If a PCI physical function is
    passed through to a Xen guest, the guest is able to
    access its memory and I/O regions before enabling
    decoding of those regions. This could result in a
    denial-of-service (unexpected NMI) on the host.

  The fix for this is incompatible with qemu versions before 2.5.

  - CVE-2017-18509
    Denis Andzakovic reported a missing type check in the
    IPv4 multicast routing implementation. A user with the
    CAP_NET_ADMIN capability (in any user namespace) could
    use this for denial-of-service (memory corruption or
    crash) or possibly for privilege escalation.

  - CVE-2018-5995
    ADLab of VenusTech discovered that the kernel logged the
    virtual addresses assigned to per-CPU data, which could
    make it easier to exploit other vulnerabilities.

  - CVE-2018-20836
    chenxiang reported a race condition in libsas, the
    kernel subsystem supporting Serial Attached SCSI (SAS)
    devices, which could lead to a use-after-free. It is not
    clear how this might be exploited.

  - CVE-2018-20856
    Xiao Jin reported a potential double-free in the block
    subsystem, in case an error occurs while initialising
    the I/O scheduler for a block device. It is not clear
    how this might be exploited.

  - CVE-2019-1125
    It was discovered that most x86 processors could
    speculatively skip a conditional SWAPGS instruction used
    when entering the kernel from user mode, and/or could
    speculatively execute it when it should be skipped. This
    is a subtype of Spectre variant 1, which could allow
    local users to obtain sensitive information from the
    kernel or other processes. It has been mitigated by
    using memory barriers to limit speculative execution.
    Systems using an i386 kernel are not affected as the
    kernel does not use SWAPGS.

  - CVE-2019-3882
    It was found that the vfio implementation did not limit
    the number of DMA mappings to device memory. A local
    user granted ownership of a vfio device could use this
    to cause a denial of service (out-of-memory condition).

  - CVE-2019-3900
    It was discovered that vhost drivers did not properly
    control the amount of work done to service requests from
    guest VMs. A malicious guest could use this to cause a
    denial-of-service (unbounded CPU usage) on the host.

  - CVE-2019-10207
    The syzkaller tool found a potential null dereference in
    various drivers for UART-attached Bluetooth adapters. A
    local user with access to a pty device or other suitable
    tty device could use this for denial-of-service
    (BUG/oops).

  - CVE-2019-10638
    Amit Klein and Benny Pinkas discovered that the
    generation of IP packet IDs used a weak hash function,
    'jhash'. This could enable tracking individual computers
    as they communicate with different remote servers and
    from different networks. The 'siphash' function is now
    used instead.

  - CVE-2019-10639
    Amit Klein and Benny Pinkas discovered that the
    generation of IP packet IDs used a weak hash function
    that incorporated a kernel virtual address. This hash
    function is no longer used for IP IDs, although it is
    still used for other purposes in the network stack.

  - CVE-2019-13631
    It was discovered that the gtco driver for USB input
    tablets could overrun a stack buffer with constant data
    while parsing the device's descriptor. A physically
    present user with a specially constructed USB device
    could use this to cause a denial-of-service (BUG/oops),
    or possibly for privilege escalation.

  - CVE-2019-13648
    Praveen Pandey reported that on PowerPC (ppc64el)
    systems without Transactional Memory (TM), the kernel
    would still attempt to restore TM state passed to the
    sigreturn() system call. A local user could use this for
    denial-of-service (oops).

  - CVE-2019-14283
    The syzkaller tool found a missing bounds check in the
    floppy disk driver. A local user with access to a floppy
    disk device, with a disk present, could use this to read
    kernel memory beyond the I/O buffer, possibly obtaining
    sensitive information.

  - CVE-2019-14284
    The syzkaller tool found a potential division-by-zero in
    the floppy disk driver. A local user with access to a
    floppy disk device could use this for denial-of-service
    (oops).

  - CVE-2019-15239
    Denis Andzakovic reported a possible use-after-free in
    the TCP sockets implementation. A local user could use
    this for denial-of-service (memory corruption or crash)
    or possibly for privilege escalation.

  - (CVE ID not yet assigned)

    The netfilter conntrack subsystem used kernel addresses
    as user-visible IDs, which could make it easier to
    exploit other security vulnerabilities.

  - XSA-300

    Julien Grall reported that Linux does not limit the
    amount of memory which a domain will attempt to balloon
    out, nor limits the amount of 'foreign / grant map'
    memory which any individual guest can consume, leading
    to denial of service conditions (for host or guests)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-20836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-20856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-1125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-3882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-3900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-14283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-14284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-15239"
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
    value:"https://packages.debian.org/source/buster/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4497"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 4.9.168-1+deb9u5.

For the stable distribution (buster), these problems were mostly fixed
in version 4.19.37-5+deb10u2 or earlier."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");
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
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dasd-extra-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dasd-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"efi-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fancontrol-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firewire-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firewire-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hyperv-daemons", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"hypervisor-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ipv6-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jffs2-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"leds-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"leds-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libbpf-dev", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libbpf4.19", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcpupower-dev", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcpupower1", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"liblockdep-dev", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"liblockdep4.19", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-arm", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-s390", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-x86", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-config-4.19", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-cpupower", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-doc-4.19", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-4kc-malta", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-5kc-malta", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-686", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-686-pae", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-amd64", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-arm64", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-armel", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-armhf", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-i386", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mips", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mips64el", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mipsel", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-ppc64el", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-s390x", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-amd64", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-arm64", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-armmp", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-armmp-lpae", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-cloud-amd64", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-common", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-common-rt", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-loongson-3", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-marvell", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-octeon", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-powerpc64le", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rpi", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-686-pae", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-amd64", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-arm64", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-armmp", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-s390x", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-4kc-malta", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-4kc-malta-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-5kc-malta", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-5kc-malta-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-pae-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-pae-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-amd64-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-amd64-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-arm64-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-arm64-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-lpae", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-lpae-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-cloud-amd64-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-cloud-amd64-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-loongson-3", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-loongson-3-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-marvell", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-marvell-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-octeon", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-octeon-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-powerpc64le", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-powerpc64le-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rpi", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rpi-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-686-pae-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-686-pae-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-amd64-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-amd64-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-arm64-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-arm64-unsigned", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-armmp", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-armmp-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-s390x", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-s390x-dbg", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-amd64-signed-template", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-arm64-signed-template", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-i386-signed-template", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-kbuild-4.19", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-libc-dev", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-perf-4.19", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-source-4.19", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-support-4.19.0-5", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"lockdep", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"rtc-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"serial-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"speakup-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"usbip", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-4kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-5kc-malta-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-armmp-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-loongson-3-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-marvell-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-octeon-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-s390x-di", reference:"4.19.37-5+deb10u2")) flag++;
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.168-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.168-1+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
