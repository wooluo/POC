#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4393. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122270);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/04 11:19:02");

  script_cve_id("CVE-2019-6454");
  script_xref(name:"DSA", value:"4393");

  script_name(english:"Debian DSA-4393-1 : systemd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Coulson discovered a flaw in systemd leading to denial of
service. An unprivileged user could take advantage of this issue to
crash PID1 by sending a specially crafted D-Bus message on the system
bus."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/systemd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/systemd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4393"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the systemd packages.

For the stable distribution (stretch), this problem has been fixed in
version 232-25+deb9u9."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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
if (deb_check(release:"9.0", prefix:"libnss-myhostname", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-mymachines", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-resolve", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-systemd", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-systemd", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libsystemd-dev", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libsystemd0", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libudev-dev", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libudev1", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libudev1-udeb", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"systemd", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-container", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-coredump", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-journal-remote", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-sysv", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"udev", reference:"232-25+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"udev-udeb", reference:"232-25+deb9u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
