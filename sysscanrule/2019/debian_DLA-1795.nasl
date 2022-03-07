#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1795-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125296);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/21  9:43:49");

  script_cve_id("CVE-2019-11473", "CVE-2019-11474", "CVE-2019-11505", "CVE-2019-11506");

  script_name(english:"Debian DLA-1795-1 : graphicsmagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in graphicsmagick, the
image processing toolkit :

CVE-2019-11473

The WriteMATLABImage function (coders/mat.c) is affected by a
heap-based buffer overflow. Remote attackers might leverage this
vulnerability to cause denial of service or any other unspecified
impact via crafted Matlab matrices.

CVE-2019-11474

The WritePDBImage function (coders/pdb.c) is affected by a heap-based
buffer overflow. Remote attackers might leverage this vulnerability to
cause denial of service or any other unspecified impact via a crafted
Palm Database file.

CVE-2019-11505 CVE-2019-11506

The XWD module (coders/xwd.c) is affected by multiple heap-based
buffer overflows and arithmetic exceptions. Remote attackers might
leverage these various flaws to cause denial of service or any other
unspecified impact via crafted XWD files.

For Debian 8 'Jessie', these problems have been fixed in version
1.3.20-3+deb8u7.

We recommend that you upgrade your graphicsmagick packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/graphicsmagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-imagemagick-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-libmagick-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphics-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");
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
if (deb_check(release:"8.0", prefix:"graphicsmagick", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-dbg", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphics-magick-perl", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick++3", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.20-3+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick3", reference:"1.3.20-3+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
