#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4462. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125905);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/14 16:15:17");

  script_cve_id("CVE-2019-12749");
  script_xref(name:"DSA", value:"4462");

  script_name(english:"Debian DSA-4462-1 : dbus - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joe Vennix discovered an authentication bypass vulnerability in dbus,
an asynchronous inter-process communication system. The implementation
of the DBUS_COOKIE_SHA1 authentication mechanism was susceptible to a
symbolic link attack. A local attacker could take advantage of this
flaw to bypass authentication and connect to a DBusServer with
elevated privileges.

The standard system and session dbus-daemons in their default
configuration are not affected by this vulnerability.

The vulnerability was addressed by upgrading dbus to a new upstream
version 1.10.28 which includes additional fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=930375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/dbus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/dbus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4462"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.10.28-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");
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
if (deb_check(release:"9.0", prefix:"dbus", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"dbus-1-dbg", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"dbus-1-doc", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"dbus-tests", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"dbus-udeb", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"dbus-user-session", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"dbus-x11", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libdbus-1-3", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libdbus-1-3-udeb", reference:"1.10.28-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libdbus-1-dev", reference:"1.10.28-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
