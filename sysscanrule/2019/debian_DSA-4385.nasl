#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4385. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121603);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/29  9:35:27");

  script_cve_id("CVE-2019-3814");
  script_xref(name:"DSA", value:"4385");

  script_name(english:"Debian DSA-4385-1 : dovecot - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"halfdog discovered an authentication bypass vulnerability in the
Dovecot email server. Under some configurations Dovecot mistakenly
trusts the username provided via authentication instead of failing. If
there is no additional password verification, this allows the attacker
to login as anyone else in the system. Only installations using :

  - auth_ssl_require_client_cert = yes
  - auth_ssl_username_from_cert = yes

are affected by this flaw."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4385"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dovecot packages.

For the stable distribution (stretch), this problem has been fixed in
version 1:2.2.27-3+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/06");
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
if (deb_check(release:"9.0", prefix:"dovecot-core", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dbg", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dev", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-gssapi", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-imapd", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-ldap", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lmtpd", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lucene", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-managesieved", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-mysql", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pgsql", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pop3d", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sieve", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-solr", reference:"1:2.2.27-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sqlite", reference:"1:2.2.27-3+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
