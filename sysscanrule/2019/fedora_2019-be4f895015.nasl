#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-be4f895015.
#

include("compat.inc");

if (description)
{
  script_id(125747);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/21 12:43:08");

  script_cve_id("CVE-2019-11038", "CVE-2019-11039", "CVE-2019-11040");
  script_xref(name:"FEDORA", value:"2019-be4f895015");

  script_name(english:"Fedora 30 : php (2019-be4f895015)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.3.6** (30 May 2019)

**cURL:**

  - Implemented FR php#72189 (Add missing CURL_VERSION_*
    constants). (Javier Spagnoletti)

**EXIF:**

  - Fixed bug php#77988 (heap-buffer-overflow on
    php_jpg_get16). (CVE-2019-11040) (Stas)

**FPM:**

  - Fixed bug php#77934 (php-fpm kill -USR2 not working).
    (Jakub Zelenka)

  - Fixed bug php#77921 (static.php.net doesn't work
    anymore). (Peter Kokot)

**GD:**

  - Fixed bug php#77943 (imageantialias($image, false); does
    not work). (cmb)

  - Fixed bug php#77973 (Uninitialized read in
    gdImageCreateFromXbm). (CVE-2019-11038) (cmb)

**Iconv:**

  - Fixed bug php#78069 (Out-of-bounds read in
    iconv.c:_php_iconv_mime_decode() due to integer
    overflow). (CVE-2019-11039). (maris dot adam)

**JSON:**

  - Fixed bug php#77843 (Use after free with json
    serializer). (Nikita)

**Opcache:**

  - Fixed possible crashes, because of inconsistent PCRE
    cache and opcache SHM reset. (Alexey Kalinin, Dmitry)

**PDO_MySQL:**

  - Fixed bug php#77944 (Wrong meta pdo_type for bigint on
    LLP64). (cmb)

**Reflection:**

  - Fixed bug php#75186 (Inconsistent reflection of
    Closure:::__invoke()). (Nikita)

**Session:**

  - Fixed bug php#77911 (Wrong warning for
    session.sid_bits_per_character). (cmb)

**SOAP:**

  - Fixed bug php#77945 (Segmentation fault when
    constructing SoapClient with WSDL_CACHE_BOTH). (Nikita)

**SPL:**

  - Fixed bug php#77024 (SplFileObject::__toString() may
    return array). (Craig Duncan)

**SQLite:**

  - Fixed bug php#77967 (Bypassing open_basedir restrictions
    via file uris). (Stas)

**Standard:**

  - Fixed bug php#77931 (Warning for array_map mentions
    wrong type). (Nikita)

  - Fixed bug php#78003 (strip_tags output change since PHP
    7.3). (cmb)

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-be4f895015"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"php-7.3.6-1.fc30")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
