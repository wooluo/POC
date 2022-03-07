#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1882-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127864);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/14 10:36:48");

  script_cve_id("CVE-2017-1000159", "CVE-2019-1010006", "CVE-2019-11459");

  script_name(english:"Debian DLA-1882-1 : atril security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A few issues were found in Atril, the MATE document viewer.

CVE-2017-1000159

When printing from DVI to PDF, the dvipdfm tool was called without
properly sanitizing the filename, which could lead to a command
injection attack via the filename.

CVE-2019-11459

The tiff_document_render() and tiff_document_get_thumbnail() did not
check the status of TIFFReadRGBAImageOriented(), leading to
uninitialized memory access if that funcion fails.

CVE-2019-1010006

Some buffer overflow checks were not properly done, leading to
application crash or possibly arbitrary code execution when opening
maliciously crafted files.

For Debian 8 'Jessie', these problems have been fixed in version
1.8.1+dfsg1-4+deb8u2.

We recommend that you upgrade your atril packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/atril"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:atril");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:atril-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:atril-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libatrildocument-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libatrildocument3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libatrildocument3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libatrilview-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libatrilview3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libatrilview3-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/27");
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
if (deb_check(release:"8.0", prefix:"atril", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"atril-common", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"atril-dbg", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libatrildocument-dev", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libatrildocument3", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libatrildocument3-dbg", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libatrilview-dev", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libatrilview3", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libatrilview3-dbg", reference:"1.8.1+dfsg1-4+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
