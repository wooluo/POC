#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1530.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125797);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/10 11:30:31");

  script_cve_id("CVE-2018-13785", "CVE-2019-7317");

  script_name(english:"openSUSE Security Update : libpng16 (openSUSE-2019-1530)");
  script_summary(english:"Check for the openSUSE-2019-1530 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libpng16 fixes the following issues :

Security issues fixed :

  - CVE-2019-7317: Fixed a use-after-free vulnerability,
    triggered when png_image_free() was called under
    png_safe_execute (bsc#1124211).

  - CVE-2018-13785: Fixed a wrong calculation of row_factor
    in the png_check_chunk_length function in pngrutil.c,
    which could haved triggered and integer overflow and
    result in an divide-by-zero while processing a crafted
    PNG file, leading to a denial of service (bsc#1100687)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124211"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng16 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-compat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-compat-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/10");
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

if ( rpm_check(release:"SUSE15.0", reference:"libpng16-16-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpng16-16-debuginfo-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpng16-compat-devel-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpng16-debugsource-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpng16-devel-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpng16-tools-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpng16-tools-debuginfo-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpng16-16-32bit-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpng16-16-32bit-debuginfo-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpng16-compat-devel-32bit-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpng16-devel-32bit-1.6.34-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpng16-16-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpng16-16-debuginfo-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpng16-compat-devel-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpng16-debugsource-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpng16-devel-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpng16-tools-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpng16-tools-debuginfo-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpng16-16-32bit-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpng16-16-32bit-debuginfo-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpng16-compat-devel-32bit-1.6.34-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpng16-devel-32bit-1.6.34-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng16-16 / libpng16-16-debuginfo / libpng16-compat-devel / etc");
}
