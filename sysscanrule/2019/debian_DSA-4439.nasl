#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4439. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124721);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-10130");
  script_xref(name:"DSA", value:"4439");

  script_name(english:"Debian DSA-4439-1 : postgresql-9.6 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dean Rasheed discovered that row security policies in the PostgreSQL
database system could be bypassed.

For additional information please refer to the upstream announcement
at https://www.postgresql.org/about/news/1939/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1939/"
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
    value:"https://www.debian.org/security/2019/dsa-4439"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-9.6 packages.

For the stable distribution (stretch), this problem has been fixed in
version 9.6.13-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");
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
if (deb_check(release:"9.0", prefix:"libecpg-compat3", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libecpg-dev", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libecpg6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpgtypes3", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpq-dev", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpq5", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-9.6-dbg", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-client-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-contrib-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-doc-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plperl-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plpython-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plpython3-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-pltcl-9.6", reference:"9.6.13-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-server-dev-9.6", reference:"9.6.13-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
