#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1313.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124582);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/10 11:30:32");

  script_cve_id("CVE-2019-9755");

  script_name(english:"openSUSE Security Update : ntfs-3g_ntfsprogs (openSUSE-2019-1313)");
  script_summary(english:"Check for the openSUSE-2019-1313 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ntfs-3g_ntfsprogs fixes the following issues :

Security issues fixed :

  - CVE-2019-9755: Fixed a heap-based buffer overflow which
    could lead to local privilege escalation (bsc#1130165).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130165"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ntfs-3g_ntfsprogs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g84-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfs-3g-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfs-3g_ntfsprogs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfsprogs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");
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

if ( rpm_check(release:"SUSE42.3", reference:"libntfs-3g-devel-2013.1.13-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libntfs-3g84-2013.1.13-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libntfs-3g84-debuginfo-2013.1.13-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfs-3g-2013.1.13-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfs-3g-debuginfo-2013.1.13-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfs-3g_ntfsprogs-debugsource-2013.1.13-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfsprogs-2013.1.13-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfsprogs-debuginfo-2013.1.13-7.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libntfs-3g-devel / libntfs-3g84 / libntfs-3g84-debuginfo / ntfs-3g / etc");
}
