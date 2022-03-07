#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1891-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127927);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-13057", "CVE-2019-13565");

  script_name(english:"Debian DLA-1891-1 : openldap security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were discovered in openldap, a server
and tools to provide a standalone directory service.

CVE-2019-13057

When the server administrator delegates rootDN (database admin)
privileges for certain databases but wants to maintain isolation
(e.g., for multi-tenant deployments), slapd does not properly stop a
rootDN from requesting authorization as an identity from another
database during a SASL bind or with a proxyAuthz (RFC 4370) control.
(It is not a common configuration to deploy a system where the server
administrator and a DB administrator enjoy different levels of trust.)

CVE-2019-13565

When using SASL authentication and session encryption, and relying on
the SASL security layers in slapd access controls, it is possible to
obtain access that would otherwise be denied via a simple bind for any
identity covered in those ACLs. After the first SASL bind is
completed, the sasl_ssf value is retained for all new non-SASL
connections. Depending on the ACL configuration, this can affect
different types of operations (searches, modifications, etc.). In
other words, a successful authorization step completed by one user
affects the authorization requirement for a different user.

For Debian 8 'Jessie', these problems have been fixed in version
2.4.40+dfsg-1+deb8u5.

We recommend that you upgrade your openldap packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openldap"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap-2.4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap-2.4-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd-smbk5pwd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
if (deb_check(release:"8.0", prefix:"ldap-utils", reference:"2.4.40+dfsg-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libldap-2.4-2", reference:"2.4.40+dfsg-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libldap-2.4-2-dbg", reference:"2.4.40+dfsg-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libldap2-dev", reference:"2.4.40+dfsg-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"slapd", reference:"2.4.40+dfsg-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"slapd-dbg", reference:"2.4.40+dfsg-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"slapd-smbk5pwd", reference:"2.4.40+dfsg-1+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
