#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1848-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126605);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/11 12:05:32");

  script_cve_id("CVE-2019-11272");

  script_name(english:"Debian DLA-1848-1 : libspring-security-2.0-java security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Spring Security support plain text passwords using
PlaintextPasswordEncoder. If an application using an affected version
of Spring Security is leveraging PlaintextPasswordEncoder and a user
has a null encoded password, a malicious user (or attacker) can
authenticate using a password of 'null'.

For Debian 8 'Jessie', this problem has been fixed in version
2.0.7.RELEASE-3+deb8u2.

We recommend that you upgrade your libspring-security-2.0-java
packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libspring-security-2.0-java"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-security-2.0-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-security-acl-2.0-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-security-core-2.0-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-security-ntlm-2.0-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-security-portlet-2.0-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-security-taglibs-2.0-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");
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
if (deb_check(release:"8.0", prefix:"libspring-security-2.0-java-doc", reference:"2.0.7.RELEASE-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-security-acl-2.0-java", reference:"2.0.7.RELEASE-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-security-core-2.0-java", reference:"2.0.7.RELEASE-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-security-ntlm-2.0-java", reference:"2.0.7.RELEASE-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-security-portlet-2.0-java", reference:"2.0.7.RELEASE-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-security-taglibs-2.0-java", reference:"2.0.7.RELEASE-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
