#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4491. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127487);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-12815");
  script_xref(name:"DSA", value:"4491");

  script_name(english:"Debian DSA-4491-1 : proftpd-dfsg - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tobias Maedel discovered that the mod_copy module of ProFTPD, a
FTP/SFTP/FTPS server, performed incomplete permission validation for
the CPFR/CPTO commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=932453"
  );
  # https://security-tracker.debian.org/tracker/source-package/proftpd-dfsg
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/proftpd-dfsg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/proftpd-dfsg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4491"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the proftpd-dfsg packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 1.3.5b-4+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 1.3.6-4+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dfsg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/04");
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
if (deb_check(release:"10.0", prefix:"proftpd-basic", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-dev", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-doc", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-mod-geoip", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-mod-ldap", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-mod-mysql", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-mod-odbc", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-mod-pgsql", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-mod-snmp", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"proftpd-mod-sqlite", reference:"1.3.6-4+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-basic", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-dev", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-doc", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-geoip", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-ldap", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-mysql", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-odbc", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-pgsql", reference:"1.3.5b-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-sqlite", reference:"1.3.5b-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
