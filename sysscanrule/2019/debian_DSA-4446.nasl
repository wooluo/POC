#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4446. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125097);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/28 12:51:26");

  script_cve_id("CVE-2019-12046");
  script_xref(name:"DSA", value:"4446");

  script_name(english:"Debian DSA-4446-1 : lemonldap-ng - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Lemonldap::NG web SSO system performed
insufficient validation of session tokens if the
'tokenUseGlobalStorage'option is enabled, which could grant users with
access to the main session database access to an anonymous session."
  );
  # https://security-tracker.debian.org/tracker/source-package/lemonldap-ng
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/lemonldap-ng"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4446"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lemonldap-ng packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.9.7-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");
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
if (deb_check(release:"9.0", prefix:"lemonldap-ng", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-doc", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-fastcgi-server", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-fr-doc", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-handler", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-common-perl", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-conf-perl", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-handler-perl", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-manager-perl", reference:"1.9.7-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-portal-perl", reference:"1.9.7-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
