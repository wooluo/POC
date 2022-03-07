#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1893-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128082);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/23 10:01:44");

  script_cve_id("CVE-2019-8675", "CVE-2019-8696");

  script_name(english:"Debian DLA-1893-1 : cups security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two issues have been found in cups, the Common UNIX Printing
System(tm).

Basically both CVEs (CVE-2019-8675 and CVE-2019-8696) are about
stack-buffer-overflow in two functions of libcup. One happens in
asn1_get_type() the other one in asn1_get_packed().

For Debian 8 'Jessie', these problems have been fixed in version
1.7.5-11+deb8u5.

We recommend that you upgrade your cups packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/cups"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-core-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");
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
if (deb_check(release:"8.0", prefix:"cups", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-bsd", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-client", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-common", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-core-drivers", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-daemon", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-dbg", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-ppdc", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"cups-server-common", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcups2", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcups2-dev", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupscgi1", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupscgi1-dev", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsimage2", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsimage2-dev", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsmime1", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsmime1-dev", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsppdc1", reference:"1.7.5-11+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsppdc1-dev", reference:"1.7.5-11+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
