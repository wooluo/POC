#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4490. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127486);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-11782", "CVE-2019-0203");
  script_xref(name:"DSA", value:"4490");

  script_name(english:"Debian DSA-4490-1 : subversion - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Subversion, a version
control system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2018-11782
    Ace Olszowka reported that the Subversion's svnserve
    server process may exit when a well-formed read-only
    request produces a particular answer, leading to a
    denial of service.

  - CVE-2019-0203
    Tomas Bortoli reported that the Subversion's svnserve
    server process may exit when a client sends certain
    sequences of protocol commands. If the server is
    configured with anonymous access enabled this could lead
    to a remote unauthenticated denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-11782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-0203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4490"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 1.9.5-1+deb9u4.

For the stable distribution (buster), these problems have been fixed
in version 1.10.4-1+deb10u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (deb_check(release:"10.0", prefix:"libapache2-mod-svn", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-dev", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-doc", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-java", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-perl", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn1", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python-subversion", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ruby-svn", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"subversion", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"subversion-tools", reference:"1.10.4-1+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-svn", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-dev", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-doc", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-java", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-perl", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn1", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python-subversion", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"ruby-svn", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"subversion", reference:"1.9.5-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"subversion-tools", reference:"1.9.5-1+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
