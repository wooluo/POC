#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1913.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128005);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-2614", "CVE-2019-2627", "CVE-2019-2628");

  script_name(english:"openSUSE Security Update : mariadb / mariadb-connector-c (openSUSE-2019-1913)");
  script_summary(english:"Check for the openSUSE-2019-1913 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb and mariadb-connector-c fixes the following
issues :

mariadb :

  - Update to version 10.2.25 (bsc#1136035)

  - CVE-2019-2628: Fixed a remote denial of service by an
    privileged attacker (bsc#1136035).

  - CVE-2019-2627: Fixed another remote denial of service by
    an privileged attacker (bsc#1136035).

  - CVE-2019-2614: Fixed a potential remote denial of
    service by an privileged attacker (bsc#1136035).

  - Fixed reading options for multiple instances if
    my${INSTANCE}.cnf is used (bsc#1132666)

mariadb-connector-c :

  - Update to version 3.1.2 (bsc#1136035)

  - Moved libmariadb.pc from /usr/lib/pkgconfig to
    /usr/lib64/pkgconfig for x86_64 (bsc#1126088) 

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136035"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb / mariadb-connector-c packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb_plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb_plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbprivate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbprivate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-connector-c-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libmariadb-devel-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb-devel-debuginfo-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb3-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb3-debuginfo-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb_plugins-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb_plugins-debuginfo-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadbprivate-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadbprivate-debuginfo-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmysqld-devel-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmysqld19-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmysqld19-debuginfo-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-bench-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-bench-debuginfo-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-client-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-client-debuginfo-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-connector-c-debugsource-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-debuginfo-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-debugsource-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-errormessages-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-galera-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-test-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-test-debuginfo-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-tools-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-tools-debuginfo-10.2.25-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmariadb3-32bit-3.1.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmariadb3-32bit-debuginfo-3.1.2-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmariadb-devel / libmariadb-devel-debuginfo / libmariadb3 / etc");
}
