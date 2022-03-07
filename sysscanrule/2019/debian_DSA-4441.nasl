#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4441. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124779);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/20  9:58:35");

  script_cve_id("CVE-2018-14773", "CVE-2018-19789", "CVE-2018-19790", "CVE-2019-10909", "CVE-2019-10910", "CVE-2019-10911", "CVE-2019-10912", "CVE-2019-10913");
  script_xref(name:"DSA", value:"4441");

  script_name(english:"Debian DSA-4441-1 : symfony - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the Symfony PHP framework
which could lead to cache bypass, authentication bypass, information
disclosure, open redirect, cross-site request forgery, deletion of
arbitrary files, or arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/symfony"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/symfony"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4441"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the symfony packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.8.7+dfsg-1.3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:symfony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");
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
if (deb_check(release:"9.0", prefix:"php-symfony", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-asset", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-browser-kit", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-class-loader", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-config", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-console", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-css-selector", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-debug", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-debug-bundle", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-dependency-injection", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-doctrine-bridge", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-dom-crawler", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-event-dispatcher", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-expression-language", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-filesystem", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-finder", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-form", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-framework-bundle", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-http-foundation", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-http-kernel", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-intl", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-ldap", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-locale", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-monolog-bridge", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-options-resolver", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-phpunit-bridge", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-process", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-property-access", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-property-info", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-proxy-manager-bridge", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-routing", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-security", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-security-bundle", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-security-core", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-security-csrf", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-security-guard", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-security-http", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-serializer", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-stopwatch", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-swiftmailer-bridge", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-templating", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-translation", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-twig-bridge", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-twig-bundle", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-validator", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-var-dumper", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-web-profiler-bundle", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"php-symfony-yaml", reference:"2.8.7+dfsg-1.3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
