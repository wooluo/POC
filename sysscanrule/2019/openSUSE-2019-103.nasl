#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-103.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(121536);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2019-6116");

  script_name(english:"openSUSE Security Update : ghostscript (openSUSE-2019-103)");
  script_summary(english:"Check for the openSUSE-2019-103 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript to version 9.26a fixes the following
issues :

Security issue fixed :

  - CVE-2019-6116: subroutines within pseudo-operators must
    themselves be pseudo-operators (bsc#1122319)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122319"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/01");
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

if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-debuginfo-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-debugsource-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-devel-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-debuginfo-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-debugsource-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-devel-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-x11-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-x11-debuginfo-9.26a-14.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspectre-debugsource-0.2.7-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspectre-devel-0.2.7-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspectre1-0.2.7-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspectre1-debuginfo-0.2.7-17.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-mini / ghostscript-mini-debuginfo / etc");
}
