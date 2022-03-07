#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1724-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126462);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/03 12:01:37");

  script_cve_id("CVE-2019-11039", "CVE-2019-11040");

  script_name(english:"SUSE SLES12 Security Update : php72 (SUSE-SU-2019:1724-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php72 fixes the following issues :

Security issues fixed :

CVE-2019-11039: Fixed a heap-buffer-overflow on php_jpg_get16
(bsc#1138173).

CVE-2019-11040: Fixed an out-of-bounds read due to an integer overflow
in iconv.c:_php_iconv_mime_decode() (bsc#1138172).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
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
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191724-1/
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
patch SUSE-SLE-SDK-12-SP4-2019-1724=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1724=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2019-1724=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php72-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-readline-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zlib-debuginfo");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php72-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php72-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-bcmath-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-bcmath-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-bz2-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-bz2-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-calendar-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-calendar-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-ctype-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-ctype-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-curl-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-curl-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-dba-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-dba-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-debugsource-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-dom-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-dom-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-enchant-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-enchant-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-exif-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-exif-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-fastcgi-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-fastcgi-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-fileinfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-fileinfo-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-fpm-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-fpm-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-ftp-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-ftp-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-gd-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-gd-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-gettext-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-gettext-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-gmp-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-gmp-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-iconv-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-iconv-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-imap-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-imap-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-intl-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-intl-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-json-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-json-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-ldap-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-ldap-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-mbstring-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-mbstring-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-mysql-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-mysql-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-odbc-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-odbc-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-opcache-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-opcache-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-openssl-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-openssl-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pcntl-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pcntl-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pdo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pdo-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pgsql-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pgsql-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-phar-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-phar-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-posix-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-posix-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pspell-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-pspell-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-readline-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-readline-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-shmop-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-shmop-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-snmp-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-snmp-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-soap-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-soap-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sockets-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sockets-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sqlite-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sqlite-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sysvmsg-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sysvmsg-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sysvsem-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sysvsem-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sysvshm-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-sysvshm-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-tidy-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-tidy-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-tokenizer-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-tokenizer-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-wddx-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-wddx-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xmlreader-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xmlreader-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xmlrpc-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xmlrpc-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xmlwriter-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xmlwriter-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xsl-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-xsl-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-zip-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-zip-debuginfo-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-zlib-7.2.5-1.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php72-zlib-debuginfo-7.2.5-1.20.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php72");
}
