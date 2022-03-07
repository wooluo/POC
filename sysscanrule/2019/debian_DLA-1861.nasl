#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1861-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126927);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/23 10:11:23");

  script_cve_id("CVE-2018-3977", "CVE-2019-12216", "CVE-2019-12217", "CVE-2019-12218", "CVE-2019-12219", "CVE-2019-12220", "CVE-2019-12221", "CVE-2019-12222", "CVE-2019-5052", "CVE-2019-7635");

  script_name(english:"Debian DLA-1861-1 : libsdl2-image security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following issues have been found in libsdl2-image, the image file
loading library.

CVE-2018-3977

Heap buffer overflow in IMG_xcf.c. This vulnerability might be
leveraged by remote attackers to cause remote code execution or denial
of service via a crafted XCF file.

CVE-2019-5052

Integer overflow and subsequent buffer overflow in IMG_pcx.c. This
vulnerability might be leveraged by remote attackers to cause remote
code execution or denial of service via a crafted PCX file.

CVE-2019-7635

Heap buffer overflow affecting Blit1to4, in IMG_bmp.c. This
vulnerability might be leveraged by remote attackers to cause denial
of service or any other unspecified impact via a crafted BMP file.

CVE-2019-12216, CVE-2019-12217, CVE-2019-12218, CVE-2019-12219,
CVE-2019-12220, CVE-2019-12221, CVE-2019-12222

Multiple out-of-bound read and write accesses affecting
IMG_LoadPCX_RW, in IMG_pcx.c. These vulnerabilities might be leveraged
by remote attackers to cause denial of service or any other
unspecified impact via a crafted PCX file.

For Debian 8 'Jessie', these problems have been fixed in version
2.0.0+dfsg-3+deb8u2.

We recommend that you upgrade your libsdl2-image packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libsdl2-image"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsdl2-image-2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsdl2-image-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsdl2-image-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/23");
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
if (deb_check(release:"8.0", prefix:"libsdl2-image-2.0-0", reference:"2.0.0+dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsdl2-image-dbg", reference:"2.0.0+dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsdl2-image-dev", reference:"2.0.0+dfsg-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
