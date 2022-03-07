#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1773.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126905);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/22 10:22:10");

  script_cve_id("CVE-2019-10130", "CVE-2019-10164");

  script_name(english:"openSUSE Security Update : postgresql10 (openSUSE-2019-1773)");
  script_summary(english:"Check for the openSUSE-2019-1773 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql10 fixes the following issues :

Security issue fixed :

  - CVE-2019-10164: Fixed buffer-overflow vulnerabilities in
    SCRAM verifier parsing (bsc#1138034).

  - CVE-2019-10130: Prevent row-level security policies from
    being bypassed via selectivity estimators (bsc#1134689).

Bug fixes :

  - For a complete list of fixes check the release notes.

    - https://www.postgresql.org/docs/10/release-10-9.html

    - https://www.postgresql.org/docs/10/release-10-8.html

    - https://www.postgresql.org/docs/10/release-10-7.html

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-7.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-9.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql10 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
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
if (release !~ "^(SUSE15\.0|SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libecpg6-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libecpg6-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpq5-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpq5-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-contrib-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-contrib-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-debugsource-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-devel-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-devel-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plperl-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plperl-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plpython-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plpython-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-pltcl-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-pltcl-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-server-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-server-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-test-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libecpg6-32bit-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libecpg6-32bit-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpq5-32bit-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-10.9-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libecpg6-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libecpg6-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpq5-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpq5-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-contrib-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-contrib-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-debugsource-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-devel-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-devel-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plperl-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plperl-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plpython-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plpython-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-pltcl-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-pltcl-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-server-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-server-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-test-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libecpg6-32bit-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libecpg6-32bit-debuginfo-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpq5-32bit-10.9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-10.9-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql10 / postgresql10-contrib / etc");
}
