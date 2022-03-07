#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1699-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122515);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/08 10:15:34");

  script_cve_id("CVE-2019-3824");

  script_name(english:"Debian DLA-1699-1 : ldb security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Garming Sam reported an out-of-bounds read in the
ldb_wildcard_compare() function of ldb, a LDAP-like embedded database,
resulting in denial of service.

For Debian 8 'Jessie', this problem has been fixed in version
2:1.1.20-0+deb8u2.

We recommend that you upgrade your ldb packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ldb"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldb1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ldb-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ldb-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");
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
if (deb_check(release:"8.0", prefix:"ldb-tools", reference:"2:1.1.20-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libldb-dev", reference:"2:1.1.20-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libldb1", reference:"2:1.1.20-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libldb1-dbg", reference:"2:1.1.20-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-ldb", reference:"2:1.1.20-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-ldb-dbg", reference:"2:1.1.20-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-ldb-dev", reference:"2:1.1.20-0+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
