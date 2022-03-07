#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1711-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122826);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/14 12:08:17");

  script_cve_id("CVE-2019-3815");

  script_name(english:"Debian DLA-1711-1 : systemd security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory leak was discovered in the backport of fixes for
CVE-2018-16864 in systemd-journald.

Function dispatch_message_real() in journald-server.c does not free
allocated memory to store the `_CMDLINE=` entry. A local attacker may
use this flaw to make systemd-journald crash.

Note that as the systemd-journald service is not restarted
automatically a restart of the service or more safely a reboot is
advised.

For Debian 8 'Jessie', this problem has been fixed in version
215-17+deb8u11.

We recommend that you upgrade your systemd packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/systemd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gudev-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgudev-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgudev-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-daemon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-daemon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-id128-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-id128-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-journal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-journal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-login-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-login0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");
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
if (deb_check(release:"8.0", prefix:"gir1.2-gudev-1.0", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libgudev-1.0-0", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libgudev-1.0-dev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-systemd", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-daemon-dev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-daemon0", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-dev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-id128-0", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-id128-dev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-journal-dev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-journal0", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-login-dev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-login0", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd0", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libudev-dev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libudev1", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libudev1-udeb", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"python3-systemd", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"systemd", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"systemd-dbg", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"systemd-sysv", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"udev", reference:"215-17+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"udev-udeb", reference:"215-17+deb8u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
