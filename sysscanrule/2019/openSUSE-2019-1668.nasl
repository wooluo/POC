#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1668.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126369);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-10130");

  script_name(english:"openSUSE Security Update : postgresql96 (openSUSE-2019-1668)");
  script_summary(english:"Check for the openSUSE-2019-1668 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql96 fixes the following issues :

Security issue fixed :

  - CVE-2019-10130: Prevent row-level security policies from
    being bypassed via selectivity estimators (bsc#1134689).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134689"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql96 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/01");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-contrib-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-contrib-debuginfo-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-debuginfo-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-debugsource-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-devel-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-devel-debuginfo-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-libs-debugsource-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plperl-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plperl-debuginfo-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plpython-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plpython-debuginfo-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-pltcl-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-pltcl-debuginfo-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-server-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-server-debuginfo-9.6.13-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-test-9.6.13-24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql96-devel / postgresql96-devel-debuginfo / etc");
}
