#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1767.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126902);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/22 10:22:10");

  script_cve_id("CVE-2019-13132");

  script_name(english:"openSUSE Security Update : zeromq (openSUSE-2019-1767)");
  script_summary(english:"Check for the openSUSE-2019-1767 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zeromq fixes the following issues :

  - CVE-2019-13132: An unauthenticated remote attacker could
    have exploited a stack overflow vulnerability on a
    server that is supposed to be protected by encryption
    and authentication to potentially gain a remote code
    execution. (bsc#1140255)

  - Correctly mark license files as licence instead of
    documentation (bsc#1082318)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140255"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zeromq packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libzmq5-4.2.3-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libzmq5-debuginfo-4.2.3-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zeromq-debugsource-4.2.3-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zeromq-devel-4.2.3-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zeromq-tools-4.2.3-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zeromq-tools-debuginfo-4.2.3-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzmq5-4.2.3-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzmq5-debuginfo-4.2.3-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zeromq-debugsource-4.2.3-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zeromq-devel-4.2.3-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zeromq-tools-4.2.3-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zeromq-tools-debuginfo-4.2.3-lp151.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzmq5 / libzmq5-debuginfo / zeromq-debugsource / zeromq-devel / etc");
}
