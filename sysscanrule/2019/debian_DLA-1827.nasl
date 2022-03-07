#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1827-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126054);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/20 11:24:23");

  script_cve_id("CVE-2019-12795");

  script_name(english:"Debian DLA-1827-1 : gvfs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Simon McVittie discovered a flaw in gvfs, the Gnome Virtual File
System. The gvfsd daemon opened a private D-Bus server socket without
configuring an authorization rule. A local attacker could connect to
this server socket and issue D-Bus method calls.

(Note that the server socket only accepts a single connection, so the
attacker would have to discover the server and connect to the socket
before its owner does.)

For Debian 8 'Jessie', this problem has been fixed in version
1.22.2-1+deb8u1.

We recommend that you upgrade your gvfs packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gvfs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs-backends");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvfs-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/20");
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
if (deb_check(release:"8.0", prefix:"gvfs", reference:"1.22.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gvfs-backends", reference:"1.22.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gvfs-bin", reference:"1.22.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gvfs-common", reference:"1.22.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gvfs-daemons", reference:"1.22.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gvfs-dbg", reference:"1.22.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gvfs-fuse", reference:"1.22.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gvfs-libs", reference:"1.22.2-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
