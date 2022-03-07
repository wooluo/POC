#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1706-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122720);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/30 16:25:06");

  script_cve_id("CVE-2018-19058", "CVE-2018-20481", "CVE-2018-20662", "CVE-2019-7310", "CVE-2019-9200");

  script_name(english:"Debian DLA-1706-1 : poppler security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were discovered in the poppler PDF
rendering shared library.

CVE-2018-19058

A reachable abort in Object.h will lead to denial of service because
EmbFile::save2 in FileSpec.cc lacks a stream check before saving an
embedded file.

CVE-2018-20481

Poppler mishandles unallocated XRef entries, which allows remote
attackers to cause a denial of service (NULL pointer dereference) via
a crafted PDF document.

CVE-2018-20662

Poppler allows attackers to cause a denial of service (application
crash and segmentation fault by crafting a PDF file in which an xref
data structure is corrupted.

CVE-2019-7310

A heap-based buffer over-read (due to an integer signedness error in
the XRef::getEntry function in XRef.cc) allows remote attackers to
cause a denial of service (application crash) or possibly have
unspecified other impact via a crafted PDF document.

CVE-2019-9200

A heap-based buffer underwrite exists in ImageStream::getLine()
located at Stream.cc that can (for example) be triggered by sending a
crafted PDF file to the pdfimages binary. It allows an attacker to
cause denial of service (segmentation fault) or possibly have
unspecified other impact.

For Debian 8 'Jessie', these problems have been fixed in version
0.26.5-2+deb8u8.

We recommend that you upgrade your poppler packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/poppler"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7310");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler46");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");
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
if (deb_check(release:"8.0", prefix:"gir1.2-poppler-0.18", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-cpp-dev", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-cpp0", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-dev", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib-dev", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib-doc", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib8", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-private-dev", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt4-4", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt4-dev", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt5-1", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt5-dev", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler46", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"poppler-dbg", reference:"0.26.5-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"poppler-utils", reference:"0.26.5-2+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
