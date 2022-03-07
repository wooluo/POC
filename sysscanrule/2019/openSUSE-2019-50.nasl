#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-50.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(121156);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 15:04:42");

  script_cve_id("CVE-2019-3500");

  script_name(english:"openSUSE Security Update : aria2 (openSUSE-2019-50)");
  script_summary(english:"Check for the openSUSE-2019-50 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for aria2 fixes the following security issue :

  - CVE-2019-3500: Metadata and potential password leaks via
    --log= (boo#1120488)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected aria2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aria2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aria2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aria2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aria2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aria2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaria2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaria2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/14");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"aria2-lang-1.33.1-lp150.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"aria2-1.33.1-lp150.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"aria2-debuginfo-1.33.1-lp150.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"aria2-debugsource-1.33.1-lp150.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"aria2-devel-1.33.1-lp150.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libaria2-0-1.33.1-lp150.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libaria2-0-debuginfo-1.33.1-lp150.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"aria2-1.24.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"aria2-debuginfo-1.24.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"aria2-debugsource-1.24.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"aria2-devel-1.24.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"aria2-lang-1.24.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libaria2-0-1.24.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libaria2-0-debuginfo-1.24.0-7.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aria2 / aria2-debuginfo / aria2-debugsource / aria2-devel / etc");
}
