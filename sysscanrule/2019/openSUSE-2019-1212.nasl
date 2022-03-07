#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1212.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124105);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/17  9:22:56");

  script_cve_id("CVE-2019-7524");

  script_name(english:"openSUSE Security Update : dovecot23 (openSUSE-2019-1212)");
  script_summary(english:"Check for the openSUSE-2019-1212 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dovecot23 fixes the following issue :

Security issue fixed :

  - CVE-2019-7524: Fixed an improper file handling which
    could result in stack oveflow allowing local root
    escalation (bsc#1130116).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130116"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot23 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-lucene-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-squat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-squat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-backend-mysql-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-backend-mysql-debuginfo-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-backend-pgsql-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-backend-pgsql-debuginfo-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-backend-sqlite-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-backend-sqlite-debuginfo-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-debuginfo-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-debugsource-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-devel-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-debuginfo-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-lucene-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-lucene-debuginfo-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-solr-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-solr-debuginfo-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-squat-2.3.3-lp150.8.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dovecot23-fts-squat-debuginfo-2.3.3-lp150.8.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot23 / dovecot23-backend-mysql / etc");
}
