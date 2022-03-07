#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1838-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126347);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/01 11:41:23");

  script_cve_id("CVE-2018-5686", "CVE-2018-6192", "CVE-2019-6130");

  script_name(english:"Debian DLA-1838-1 : mupdf security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several minor issues have been fixed in mupdf, a lightweight PDF
viewer tailored for display of high quality anti-aliased graphics.

CVE-2018-5686

In MuPDF, there was an infinite loop vulnerability and application
hang in the pdf_parse_array function (pdf/pdf-parse.c) because EOF not
having been considered. Remote attackers could leverage this
vulnerability to cause a denial of service via a crafted PDF file.

CVE-2019-6130

MuPDF had a SEGV in the function fz_load_page of the fitz/document.c
file, as demonstrated by mutool. This was related to page-number
mishandling in cbz/mucbz.c, cbz/muimg.c, and svg/svg-doc.c.

CVE-2018-6192

In MuPDF, the pdf_read_new_xref function in pdf/pdf-xref.c allowed
remote attackers to cause a denial of service (segmentation violation
and application crash) via a crafted PDF file.

For Debian 8 'Jessie', these problems have been fixed in version
1.5-1+deb8u6.

We recommend that you upgrade your mupdf packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mupdf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libmupdf-dev, mupdf, and mupdf-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmupdf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mupdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mupdf-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/01");
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
if (deb_check(release:"8.0", prefix:"libmupdf-dev", reference:"1.5-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"mupdf", reference:"1.5-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"mupdf-tools", reference:"1.5-1+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
