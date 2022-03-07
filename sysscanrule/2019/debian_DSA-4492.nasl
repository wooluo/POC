#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4492. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127488);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id("CVE-2019-10208");
  script_xref(name:"DSA", value:"4492");
  script_xref(name:"IAVB", value:"2019-B-0072");

  script_name(english:"Debian DSA-4492-1 : postgresql-9.6 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A issue has been discovered in the PostgreSQL database system, which
could result in privilege escalation.

For additional information please refer to the upstream announcement
at https://www.postgresql.org/about/news/1960/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1960/"
  );
  # https://security-tracker.debian.org/tracker/source-package/postgresql-9.6
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/postgresql-9.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4492"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-9.6 packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 9.6.15-0+deb9u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"9.0", prefix:"libecpg-compat3", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libecpg-dev", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libecpg6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpgtypes3", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpq-dev", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpq5", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-9.6-dbg", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-client-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-contrib-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-doc-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plperl-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plpython-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plpython3-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-pltcl-9.6", reference:"9.6.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-server-dev-9.6", reference:"9.6.15-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
