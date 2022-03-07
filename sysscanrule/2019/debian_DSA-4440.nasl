#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4440. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124722);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/10 10:59:32");

  script_cve_id("CVE-2018-5743", "CVE-2018-5745", "CVE-2019-6465");
  script_xref(name:"DSA", value:"4440");

  script_name(english:"Debian DSA-4440-1 : bind9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in the BIND DNS server :

  - CVE-2018-5743
    Connection limits were incorrectly enforced.

  - CVE-2018-5745
    The 'managed-keys' feature was susceptible to denial of
    service by triggering an assert.

  - CVE-2019-6465
    ACLs for zone transfers were incorrectly enforced for
    dynamically loadable zones (DLZs)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-6465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4440"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the stable distribution (stretch), these problems have been fixed
in version 1:9.10.3.dfsg.P4-12.3+deb9u5."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

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
if (deb_check(release:"9.0", prefix:"bind9", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"bind9-doc", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"bind9-host", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"bind9utils", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"dnsutils", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"host", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libbind-dev", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libbind-export-dev", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libbind9-140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libdns-export162", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libdns-export162-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libdns162", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libirs-export141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libirs-export141-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libirs141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisc-export160", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisc-export160-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisc160", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc-export140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc-export140-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisccc140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg-export140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg-export140-udeb", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libisccfg140", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"liblwres141", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"lwresd", reference:"1:9.10.3.dfsg.P4-12.3+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
