#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4470. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126129);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-10162", "CVE-2019-10163");
  script_xref(name:"DSA", value:"4470");

  script_name(english:"Debian DSA-4470-1 : pdns - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in pdns, an authoritative DNS
server which may result in denial of service via malformed zone
records and excessive NOTIFY packets in a master/slave setup."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/pdns"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/pdns"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4470"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pdns packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.0.3-1+deb9u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/24");
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
if (deb_check(release:"9.0", prefix:"pdns-backend-bind", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-geoip", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-ldap", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-lua", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-mydns", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-mysql", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-odbc", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-opendbx", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-pgsql", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-pipe", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-remote", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-sqlite3", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-backend-tinydns", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-server", reference:"4.0.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"pdns-tools", reference:"4.0.3-1+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
