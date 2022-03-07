#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1720-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122932);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/19 11:02:10");

  script_cve_id("CVE-2019-9215");

  script_name(english:"Debian DLA-1720-1 : liblivemedia security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that liblivemedia, the LIVE555 RTSP server library,
is vulnerable to an invalid memory access when processing the
Authorization header field. Remote attackers could leverage this
vulnerability to possibly trigger code execution or denial of service
(OOB access and application crash) via a crafted HTTP header.

For Debian 8 'Jessie', this problem has been fixed in version
2014.01.13-1+deb8u3.

We recommend that you upgrade your liblivemedia packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/liblivemedia"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbasicusageenvironment0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgroupsock1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblivemedia-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblivemedia23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libusageenvironment1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:livemedia-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/19");
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
if (deb_check(release:"8.0", prefix:"libbasicusageenvironment0", reference:"2014.01.13-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libgroupsock1", reference:"2014.01.13-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"liblivemedia-dev", reference:"2014.01.13-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"liblivemedia23", reference:"2014.01.13-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libusageenvironment1", reference:"2014.01.13-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"livemedia-utils", reference:"2014.01.13-1+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
