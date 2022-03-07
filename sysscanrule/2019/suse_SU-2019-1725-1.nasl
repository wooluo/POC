#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1725-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126463);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/03 12:01:37");

  script_cve_id("CVE-2019-11039", "CVE-2019-11040");

  script_name(english:"SUSE SLES12 Security Update : php7 (SUSE-SU-2019:1725-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php7 fixes the following issues :

Security issues fixed :

CVE-2019-11039: Fixed a heap-buffer-overflow on php_jpg_get16
(bsc#1138173).

CVE-2019-11040: Fixed an out-of-bounds read due to an integer overflow
in iconv.c:_php_iconv_mime_decode() (bsc#1138172).

Other issue addressed: Enable php7 testsuite (bsc#1119396

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11039/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11040/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191725-1/
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
patch SUSE-SLE-SDK-12-SP4-2019-1725=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1725=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2019-1725=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/03");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php7-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php7-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-bcmath-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-bcmath-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-bz2-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-bz2-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-calendar-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-calendar-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-ctype-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-ctype-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-curl-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-curl-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-dba-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-dba-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-debugsource-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-dom-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-dom-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-enchant-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-enchant-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-exif-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-exif-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-fastcgi-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-fastcgi-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-fileinfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-fileinfo-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-fpm-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-fpm-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-ftp-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-ftp-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-gd-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-gd-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-gettext-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-gettext-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-gmp-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-gmp-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-iconv-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-iconv-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-imap-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-imap-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-intl-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-intl-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-json-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-json-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-ldap-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-ldap-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-mbstring-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-mbstring-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-mcrypt-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-mcrypt-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-mysql-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-mysql-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-odbc-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-odbc-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-opcache-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-opcache-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-openssl-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-openssl-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pcntl-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pcntl-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pdo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pdo-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pgsql-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pgsql-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-phar-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-phar-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-posix-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-posix-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pspell-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-pspell-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-shmop-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-shmop-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-snmp-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-snmp-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-soap-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-soap-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sockets-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sockets-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sqlite-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sqlite-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sysvmsg-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sysvmsg-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sysvsem-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sysvsem-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sysvshm-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-sysvshm-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-tokenizer-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-tokenizer-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-wddx-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-wddx-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xmlreader-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xmlreader-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xmlrpc-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xmlrpc-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xmlwriter-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xmlwriter-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xsl-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-xsl-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-zip-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-zip-debuginfo-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-zlib-7.0.7-50.80.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php7-zlib-debuginfo-7.0.7-50.80.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php7");
}
