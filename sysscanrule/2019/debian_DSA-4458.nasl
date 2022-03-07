#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4458. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125784);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/10 11:30:31");

  script_cve_id("CVE-2019-11356");
  script_xref(name:"DSA", value:"4458");

  script_name(english:"Debian DSA-4458-1 : cyrus-imapd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was discovered in the CalDAV feature in httpd of the Cyrus IMAP
server, leading to denial of service or potentially the execution of
arbitrary code via a crafted HTTP PUT operation for an event with a
long iCalendar property name."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/cyrus-imapd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/cyrus-imapd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4458"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-imapd packages.

For the stable distribution (stretch), this problem has been fixed in
version 2.5.10-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/10");
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
if (deb_check(release:"9.0", prefix:"cyrus-admin", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-caldav", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-clients", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-common", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-dev", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-doc", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-imapd", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-murder", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-nntpd", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-pop3d", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-replication", reference:"2.5.10-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcyrus-imap-perl", reference:"2.5.10-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
