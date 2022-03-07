#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4494. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127490);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-14744");
  script_xref(name:"DSA", value:"4494");

  script_name(english:"Debian DSA-4494-1 : kconfig - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dominik Penner discovered that KConfig, the KDE configuration settings
framework, supported a feature to define shell command execution in
.desktop files. If a user is provided with a malformed .desktop file
(e.g. if it's embedded into a downloaded archive and it gets opened in
a file browser) arbitrary commands could get executed. This update
removes this feature."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/kconfig"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/kconfig"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/kconfig"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4494"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kconfig packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 5.28.0-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 5.54.0-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kconfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/09");
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
if (deb_check(release:"10.0", prefix:"libkf5config-bin", reference:"5.54.0-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkf5config-data", reference:"5.54.0-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkf5config-dev", reference:"5.54.0-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkf5config-dev-bin", reference:"5.54.0-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkf5config-doc", reference:"5.54.0-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkf5configcore5", reference:"5.54.0-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkf5configgui5", reference:"5.54.0-1+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkf5config-bin", reference:"5.28.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkf5config-bin-dev", reference:"5.28.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkf5config-data", reference:"5.28.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkf5config-dev", reference:"5.28.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkf5configcore5", reference:"5.28.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libkf5configgui5", reference:"5.28.0-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
