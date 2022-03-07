#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1818-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125926);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/17 16:04:23");

  script_cve_id("CVE-2019-12749");

  script_name(english:"Debian DLA-1818-1 : dbus security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joe Vennix discovered an authentication bypass vulnerability in dbus,
an asynchronous inter-process communication system. The implementation
of the DBUS_COOKIE_SHA1 authentication mechanism was susceptible to a
symbolic link attack. A local attacker could take advantage of this
flaw to bypass authentication and connect to a DBusServer with
elevated privileges.

For Debian 8 'Jessie', this problem has been fixed in version
1.8.22-0+deb8u2.

We recommend that you upgrade your dbus packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/dbus"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus-1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdbus-1-3-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdbus-1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/17");
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
if (deb_check(release:"8.0", prefix:"dbus", reference:"1.8.22-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dbus-1-dbg", reference:"1.8.22-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dbus-1-doc", reference:"1.8.22-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dbus-udeb", reference:"1.8.22-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dbus-x11", reference:"1.8.22-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libdbus-1-3", reference:"1.8.22-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libdbus-1-3-udeb", reference:"1.8.22-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libdbus-1-dev", reference:"1.8.22-0+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
