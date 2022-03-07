#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1325-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125457);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/28 12:51:24");

  script_cve_id("CVE-2019-11034", "CVE-2019-11035", "CVE-2019-11036", "CVE-2019-9637", "CVE-2019-9638", "CVE-2019-9639", "CVE-2019-9640", "CVE-2019-9675");

  script_name(english:"SUSE SLES12 Security Update : php5 (SUSE-SU-2019:1325-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php5 fixes the following issues :

Security issues fixed :

CVE-2019-11034: Fixed a heap-buffer overflow in php_ifd_get32si()
(bsc#1132838).

CVE-2019-11035: Fixed a heap-buffer overflow in exif_iif_add_value()
(bsc#1132837).

CVE-2019-9637: Fixed a potential information disclosure in rename()
(bsc#1128892).

CVE-2019-9675: Fixed a potential buffer overflow in
phar_tar_writeheaders_int() (bsc#1128886).

CVE-2019-9638: Fixed an uninitialized read in
exif_process_IFD_in_MAKERNOTE() related to value_len (bsc#1128889).

CVE-2019-9639: Fixed an uninitialized read in
exif_process_IFD_in_MAKERNOTE() related to data_len (bsc#1128887).

CVE-2019-9640: Fixed an invalid Read in exif_process_SOFn()
(bsc#1128883).

CVE-2019-11036: Fixed buffer over-read in exif_process_IFD_TAG
function leading to information disclosure (bsc#1134322).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11034/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11035/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11036/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9637/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9638/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9675/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191325-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-1325=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1325=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2019-1325=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-suhosin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debugsource-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-debuginfo-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-5.5.14-109.58.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-debuginfo-5.5.14-109.58.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5");
}
