#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-ec40d89812.
#

include("compat.inc");

if (description)
{
  script_id(127535);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-11041", "CVE-2019-11042");
  script_xref(name:"FEDORA", value:"2019-ec40d89812");

  script_name(english:"Fedora 30 : php (2019-ec40d89812)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.21** (01 Aug 2019)

**Date:**

  - Fixed bug php#69044 (discrepency between time and
    microtime). (krakjoe)

**EXIF:**

  - Fixed bug php#78256 (heap-buffer-overflow on
    exif_process_user_comment). (CVE-2019-11042) (Stas)

  - Fixed bug php#78222 (heap-buffer-overflow on
    exif_scan_thumbnail). (CVE-2019-11041) (Stas)

**Fileinfo:**

  - Fixed bug php#78183 (finfo_file shows wrong mime-type
    for .tga file). (Joshua Westerheide)

**FTP:**

  - Fixed bug php#77124 (FTP with SSL memory leak). (Nikita)

**Libxml:**

  - Fixed bug php#78279 (libxml_disable_entity_loader
    settings is shared between requests (cgi-fcgi)).
    (Nikita)

**LiteSpeed:**

  - Updated to LiteSpeed SAPI V7.4.3 (increased response
    header count limit from 100 to 1000, added crash handler
    to cleanly shutdown PHP request, added CloudLinux
    mod_lsapi mode). (George Wang)

  - Fixed bug php#76058 (After 'POST data can't be
    buffered', using php://input makes huge tmp files).
    (George Wang)

**Openssl:**

  - Fixed bug php#78231 (Segmentation fault upon
    stream_socket_accept of exported socket-to-stream).
    (Nikita)

**OPcache:**

  - Fixed bug php#78189 (file cache strips last character of
    uname hash). (cmb)

  - Fixed bug php#78202 (Opcache stats for cache hits are
    capped at 32bit NUM). (cmb)

  - Fixed bug php#78291 (opcache_get_configuration doesn't
    list all directives). (Andrew Collington)

**Phar:**

  - Fixed bug php#77919 (Potential UAF in Phar RSHUTDOWN).
    (cmb)

**Phpdbg:**

  - Fixed bug php#78297 (Include unexistent file memory
    leak). (Nikita)

**PDO_Sqlite:**

  - Fixed bug php#78192 (SegFault when reuse statement after
    schema has changed). (Vincent Quatrevieux)

**Standard:**

  - Fixed bug php#78241 (touch() does not handle dates after
    2038 in PHP 64-bit). (cmb)

  - Fixed bug php#78269 (password_hash uses weak options for
    argon2). (Remi)

**XMLRPC:**

  - Fixed bug php#78173 (XML-RPC mutates immutable objects
    during encoding). (Asher Baker)

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-ec40d89812"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (rpm_check(release:"FC30", reference:"php-7.3.8-1.fc30")) flag++;


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
