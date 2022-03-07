#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1629.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126304);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/27 13:33:21");

  script_cve_id("CVE-2019-11372", "CVE-2019-11373");

  script_name(english:"openSUSE Security Update : libmediainfo (openSUSE-2019-1629)");
  script_summary(english:"Check for the openSUSE-2019-1629 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libmediainfo fixes the following issues :

  - CVE-2019-11373: Fixed out-of-bounds read in function
    File__Analyze:Get_L8 (boo#1133156)

  - CVE-2019-11372: Fixed out-of-bounds read in function
    MediaInfoLib:File__Tags_Helper:Synched_Test
    (boo#1133157)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133157"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmediainfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/27");
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

if ( rpm_check(release:"SUSE15.0", reference:"libmediainfo-debugsource-18.03-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmediainfo-devel-18.03-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmediainfo0-18.03-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmediainfo0-debuginfo-18.03-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmediainfo0-32bit-18.03-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmediainfo0-32bit-debuginfo-18.03-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmediainfo-debugsource-0.7.96-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmediainfo-devel-0.7.96-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmediainfo0-0.7.96-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmediainfo0-debuginfo-0.7.96-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmediainfo0-32bit-0.7.96-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmediainfo0-debuginfo-32bit-0.7.96-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmediainfo-debugsource / libmediainfo-devel / libmediainfo0 / etc");
}
