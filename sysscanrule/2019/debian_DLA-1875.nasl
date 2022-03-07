#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1875-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127484);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-11187");

  script_name(english:"Debian DLA-1875-1 : fusiondirectory security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In FusionDirectory, an LDAP web-frontend written in PHP (originally
derived GOsa&sup2; 2.6.x), a vulnerability was found that could
theoretically lead to unauthorized access to the LDAP database managed
with FusionDirectory. LDAP queries' result status ('Success') checks
had not been strict enough. The resulting output containing the word
'Success' anywhere in the returned data during login connection
attempts would have returned 'LDAP success' to FusionDirectory and
possibly grant unwanted access.

For Debian 8 'Jessie', this problem has been fixed in version
1.0.8.2-5+deb8u2.

We recommend that you upgrade your fusiondirectory packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/fusiondirectory"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-addressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-alias");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-alias-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-apache2-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-argonaut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-argonaut-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-asterisk-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-autofs-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-cyrus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-cyrus-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dashboard-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-database-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-debconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-debconf-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-desktop-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-desktop-management-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-developers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dhcp-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dns-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dovecot-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dsa-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fai-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fax-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-freeradius-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fusioninventory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fusioninventory-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-game");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-gpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-gpg-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ipmi-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-kolab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-kolab-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ldapdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ldapmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-mail-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-nagios-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-netgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-netgroups-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-openstack-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-openstack-compute-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-opsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-opsi-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-puppet-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-pureftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-pureftpd-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-quota");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-quota-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-repository-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-samba-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sogo-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-squid-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ssh-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sudo-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-supann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-supann-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sympa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sympa-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-systems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-systems-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-uw-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-weblink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-weblink-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-webservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-webservice-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-smarty3-acl-render");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-webservice-shell");
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
if (deb_check(release:"8.0", prefix:"fusiondirectory", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-addressbook", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-alias", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-alias-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-apache2", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-apache2-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-argonaut", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-argonaut-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-asterisk", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-asterisk-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-autofs", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-autofs-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-cyrus", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-cyrus-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dashboard", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dashboard-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-database-connector", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-debconf", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-debconf-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-desktop-management", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-desktop-management-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-developers", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dhcp", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dhcp-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dns", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dns-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dovecot", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dovecot-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dsa", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-dsa-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-fai", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-fai-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-fax", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-fax-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-freeradius", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-freeradius-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-fusioninventory", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-fusioninventory-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-game", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-gpg", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-gpg-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-ipmi", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-ipmi-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-kolab", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-kolab-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-ldapdump", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-ldapmanager", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-mail", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-mail-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-nagios", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-nagios-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-netgroups", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-netgroups-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-openstack-compute", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-openstack-compute-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-opsi", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-opsi-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-puppet", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-puppet-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-pureftpd", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-pureftpd-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-quota", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-quota-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-repository", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-repository-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-rsyslog", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-samba", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-samba-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-sogo", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-sogo-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-squid", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-squid-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-ssh", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-ssh-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-sudo", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-sudo-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-supann", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-supann-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-sympa", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-sympa-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-systems", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-systems-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-uw-imap", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-weblink", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-weblink-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-webservice", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-plugin-webservice-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-schema", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-smarty3-acl-render", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-theme-oxygen", reference:"1.0.8.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fusiondirectory-webservice-shell", reference:"1.0.8.2-5+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
