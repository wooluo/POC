#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1689-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122431);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/26 13:20:35");

  script_cve_id("CVE-2017-7608", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613", "CVE-2018-16062", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7665");

  script_name(english:"Debian DLA-1689-1 : elfutils security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues in elfutils, a collection of utilities to handle ELF
objects, have been found either by fuzzing or by using an
AddressSanitizer.

CVE-2019-7665 Due to a heap-buffer-overflow problem in function
elf32_xlatetom() a crafted ELF input can cause segmentation faults.

CVE-2019-7150 Add sanity check for partial core file dynamic data
read.

CVE-2019-7149 Due to a heap-buffer-overflow problem in function
read_srclines() a crafted ELF input can cause segmentation faults.

CVE-2018-18521 By using a crafted ELF file, containing a zero
sh_entsize, a divide-by-zero vulnerability could allow remote
attackers to cause a denial of service (application crash).

CVE-2018-18520 By fuzzing an Invalid Address Deference problem in
function elf_end has been found.

CVE-2018-18310 By fuzzing an Invalid Address Read problem in eu-stack
has been found.

CVE-2018-16062 By using an AddressSanitizer a heap-buffer-overflow has
been found.

CVE-2017-7613 By using fuzzing it was found that an allocation failure
was not handled properly.

CVE-2017-7612 By using a crafted ELF file, containing an invalid
sh_entsize, a remote attackers could cause a denial of service
(application crash).

CVE-2017-7611 By using a crafted ELF file a remote attackers could
cause a denial of service (application crash).

CVE-2017-7610 By using a crafted ELF file a remote attackers could
cause a denial of service (application crash).

CVE-2017-7608 By fuzzing a heap based buffer overflow has been
detected.

For Debian 8 'Jessie', these problems have been fixed in version
0.159-4.2+deb8u1.

We recommend that you upgrade your elfutils packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/elfutils"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libelf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libelf1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/26");
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
if (deb_check(release:"8.0", prefix:"elfutils", reference:"0.159-4.2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libasm-dev", reference:"0.159-4.2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libasm1", reference:"0.159-4.2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libdw-dev", reference:"0.159-4.2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libdw1", reference:"0.159-4.2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libelf-dev", reference:"0.159-4.2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libelf1", reference:"0.159-4.2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
