#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1759-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124217);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/23 10:32:08");

  script_cve_id("CVE-2019-1787", "CVE-2019-1788", "CVE-2019-1789");

  script_name(english:"Debian DLA-1759-1 : clamav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Out-of-bounds read and write conditions have been fixed in clamav.

CVE-2019-1787

An out-of-bounds heap read condition may occur when scanning PDF
documents. The defect is a failure to correctly keep track of the
number of bytes remaining in a buffer when indexing file data.

CVE-2019-1788

An out-of-bounds heap write condition may occur when scanning OLE2
files such as Microsoft Office 97-2003 documents. The invalid write
happens when an invalid pointer is mistakenly used to initialize a
32bit integer to zero. This is likely to crash the application.

CVE-2019-1789

An out-of-bounds heap read condition may occur when scanning PE files
(i.e. Windows EXE and DLL files) that have been packed using Aspack as
a result of inadequate bound-checking.

For Debian 8 'Jessie', these problems have been fixed in version
0.100.3+dfsg-0+deb8u1.

We recommend that you upgrade your clamav packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/04/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/clamav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/23");
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
if (deb_check(release:"8.0", prefix:"clamav", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamav-base", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamav-daemon", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamav-dbg", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamav-docs", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamav-freshclam", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamav-milter", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamav-testfiles", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"clamdscan", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libclamav-dev", reference:"0.100.3+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libclamav7", reference:"0.100.3+dfsg-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
