#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-323.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122772);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/28 10:07:15");

  script_cve_id("CVE-2019-3817");

  script_name(english:"openSUSE Security Update : libcomps (openSUSE-2019-323)");
  script_summary(english:"Check for the openSUSE-2019-323 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libcomps fixes the following issue: &#9; Security
issue fixed :

  - CVE-2019-3817: Fixed a use-after-free vulnerability in
    comps_objmradix.c:comps_objmrtree_unite() function where
    could allow to application crash or code execution
    (bsc#1122841)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122841"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libcomps packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcomps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcomps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcomps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcomps0_1_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcomps0_1_6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-libcomps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libcomps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/12");
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

if ( rpm_check(release:"SUSE15.0", reference:"libcomps-debuginfo-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcomps-debugsource-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcomps-devel-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcomps0_1_6-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcomps0_1_6-debuginfo-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python2-libcomps-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python2-libcomps-debuginfo-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-libcomps-0.1.8-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-libcomps-debuginfo-0.1.8-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcomps-debuginfo / libcomps-debugsource / libcomps-devel / etc");
}
