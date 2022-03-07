#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1635-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121233);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/04 10:02:18");

  script_cve_id("CVE-2019-3811");

  script_name(english:"Debian DLA-1635-1 : sssd security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was found in sssd. If a user was configured with no
home directory set, sssd would return '/' (the root directory) instead
of '' (the empty string / no home directory). This could impact
services that restrict the user's filesystem access to within their
home directory through chroot() etc.

For Debian 8 'Jessie', this problem has been fixed in version
1.11.7-3+deb8u2.

We recommend that you upgrade your sssd packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/sssd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");
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
if (deb_check(release:"8.0", prefix:"libipa-hbac-dev", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libipa-hbac0", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libnss-sss", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-sss", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-idmap-dev", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-idmap0", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-nss-idmap-dev", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-nss-idmap0", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-sudo", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-libipa-hbac", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-libsss-nss-idmap", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-sss", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ad", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ad-common", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-common", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-dbus", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ipa", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-krb5", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-krb5-common", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ldap", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-proxy", reference:"1.11.7-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-tools", reference:"1.11.7-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
