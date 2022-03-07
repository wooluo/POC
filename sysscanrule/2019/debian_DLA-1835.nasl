#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1835-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126223);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/26 10:34:07");

  script_cve_id("CVE-2019-9740", "CVE-2019-9947");

  script_name(english:"Debian DLA-1835-2 : python3.4 regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update issued as DLA-1835-1 caused a regression in the http.client
library in Python 3.4 which was broken by the patch intended to fix
CVE-2019-9740 and CVE-2019-9947.

For Debian 8 'Jessie', this problem has been fixed in version
3.4.2-1+deb8u4.

We recommend that you upgrade your python3.4 packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/python3.4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-venv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");
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
if (deb_check(release:"8.0", prefix:"idle-python3.4", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-dbg", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-dev", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-minimal", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-stdlib", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-testsuite", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-dbg", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-dev", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-doc", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-examples", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-minimal", reference:"3.4.2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-venv", reference:"3.4.2-1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
