#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1860-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126926);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/23 10:11:23");

  script_cve_id("CVE-2016-4609", "CVE-2016-4610", "CVE-2019-13117", "CVE-2019-13118");

  script_name(english:"Debian DLA-1860-1 : libxslt security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in libxslt the XSLT 1.0 processing
library.

CVE-2016-4610

Invalid memory access leading to DoS at exsltDynMapFunction. libxslt
allows remote attackers to cause a denial of service (memory
corruption) or possibly have unspecified other impact via unknown
vectors.

CVE-2016-4609

Out-of-bounds read at xmlGetLineNoInternal() libxslt allows remote
attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via unknown vectors.

CVE-2019-13117

An xsl:number with certain format strings could lead to an
uninitialized read in xsltNumberFormatInsertNumbers. This could allow
an attacker to discern whether a byte on the stack contains the
characters A, a, I, i, or 0, or any other character.

CVE-2019-13118

A type holding grouping characters of an xsl:number instruction was
too narrow and an invalid character/length combination could be passed
to xsltNumberFormatDecimal, leading to a read of uninitialized stack
data.

For Debian 8 'Jessie', these problems have been fixed in version
1.1.28-2+deb8u5.

We recommend that you upgrade your libxslt packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libxslt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxslt1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxslt1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxslt1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxslt1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xsltproc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/22");
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
if (deb_check(release:"8.0", prefix:"libxslt1-dbg", reference:"1.1.28-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libxslt1-dev", reference:"1.1.28-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libxslt1.1", reference:"1.1.28-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"python-libxslt1", reference:"1.1.28-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"python-libxslt1-dbg", reference:"1.1.28-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"xsltproc", reference:"1.1.28-2+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
