#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4428. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123836);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2019-3842");
  script_xref(name:"DSA", value:"4428");

  script_name(english:"Debian DSA-4428-1 : systemd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jann Horn discovered that the PAM module in systemd insecurely uses
the environment and lacks seat verification permitting spoofing an
active session to PolicyKit. A remote attacker with SSH access can
take advantage of this issue to gain PolicyKit privileges that are
normally only granted to clients in an active session on the local
console."
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
    value:"https://www.debian.org/security/2019/dsa-4428"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the systemd packages.

For the stable distribution (stretch), this problem has been fixed in
version 232-25+deb9u11.

This update includes updates previously scheduled to be released in
the stretch 9.9 point release."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");
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
if (deb_check(release:"9.0", prefix:"libnss-myhostname", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-mymachines", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-resolve", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-systemd", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-systemd", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libsystemd-dev", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libsystemd0", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libudev-dev", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libudev1", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libudev1-udeb", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"systemd", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-container", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-coredump", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-journal-remote", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"systemd-sysv", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"udev", reference:"232-25+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"udev-udeb", reference:"232-25+deb9u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
