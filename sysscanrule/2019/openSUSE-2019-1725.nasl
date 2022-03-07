#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1725.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126889);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/22 10:22:10");

  script_cve_id("CVE-2019-12209", "CVE-2019-12210", "CVE-2019-9578");

  script_name(english:"openSUSE Security Update : libu2f-host / pam_u2f (openSUSE-2019-1725)");
  script_summary(english:"Check for the openSUSE-2019-1725 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libu2f-host and pam_u2f to version 1.0.8 fixes the
following issues :

Security issues fixed for libu2f-host :

  - CVE-2019-9578: Fixed a memory leak due to a wrong parse
    of init's response (bsc#1128140).

Security issues fixed for pam_u2f :

  - CVE-2019-12209: Fixed an issue where symlinks in the
    user's directory were followed (bsc#1135729).

  - CVE-2019-12210: Fixed file descriptor leaks
    (bsc#1135727).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135729"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libu2f-host / pam_u2f packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libu2f-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libu2f-host-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libu2f-host-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libu2f-host0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libu2f-host0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_u2f");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_u2f-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_u2f-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:u2f-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:u2f-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/19");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libu2f-host-debuginfo-1.1.6-lp150.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libu2f-host-debugsource-1.1.6-lp150.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libu2f-host-devel-1.1.6-lp150.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libu2f-host0-1.1.6-lp150.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libu2f-host0-debuginfo-1.1.6-lp150.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pam_u2f-1.0.8-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pam_u2f-debuginfo-1.0.8-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pam_u2f-debugsource-1.0.8-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"u2f-host-1.1.6-lp150.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"u2f-host-debuginfo-1.1.6-lp150.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libu2f-host-debuginfo / libu2f-host-debugsource / libu2f-host-devel / etc");
}
