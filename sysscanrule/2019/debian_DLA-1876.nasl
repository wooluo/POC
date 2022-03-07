#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1876-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127485);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-11187");

  script_name(english:"Debian DLA-1876-1 : gosa security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In GOsa&sup2;, an LDAP web-frontend written in PHP, a vulnerability
was found that could theoretically have lead to unauthorized access to
the LDAP database managed with FusionDirectory. LDAP queries' result
status ('Success') checks had not been strict enough. The resulting
output containing the word 'Success' anywhere in the returned data
during login connection attempts would have returned 'LDAP success' to
FusionDirectory and possibly grant unwanted access.

For Debian 8 'Jessie', this problem has been fixed in version
2.7.4+reloaded2-1+deb8u4.

We recommend that you upgrade your gosa packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gosa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-help-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-connectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-dhcp-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-dns-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-fai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-fai-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-gofax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-gofon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-goto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-kolab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-kolab-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-ldapmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-mit-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-mit-krb5-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-nagios-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-netatalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-opengroupware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-openxchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-openxchange-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-opsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-phpgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-phpgw-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-phpscheduleit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-phpscheduleit-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-pptp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-pptp-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-pureftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-pureftpd-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-rolemanagement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-scalix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-ssh-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-sudo-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-systems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-uw-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-plugin-webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa-schema");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/10");
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
if (deb_check(release:"8.0", prefix:"gosa", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-desktop", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-dev", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-help-de", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-help-en", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-help-fr", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-help-nl", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-connectivity", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-dhcp", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-dhcp-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-dns", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-dns-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-fai", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-fai-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-gofax", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-gofon", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-goto", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-kolab", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-kolab-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-ldapmanager", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-mail", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-mit-krb5", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-mit-krb5-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-nagios", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-nagios-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-netatalk", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-opengroupware", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-openxchange", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-openxchange-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-opsi", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-phpgw", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-phpgw-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-phpscheduleit", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-phpscheduleit-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-pptp", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-pptp-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-pureftpd", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-pureftpd-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-rolemanagement", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-rsyslog", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-samba", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-scalix", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-squid", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-ssh", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-ssh-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-sudo", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-sudo-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-systems", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-uw-imap", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-plugin-webdav", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gosa-schema", reference:"2.7.4+reloaded2-1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
