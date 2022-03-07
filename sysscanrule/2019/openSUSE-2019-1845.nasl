#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1845.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127834);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/13 10:54:56");

  script_cve_id("CVE-2019-11922");

  script_name(english:"openSUSE Security Update : zstd (openSUSE-2019-1845)");
  script_summary(english:"Check for the openSUSE-2019-1845 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zstd to version 1.4.2 fixes the following issues :

Security issues fixed :

&#9; - CVE-2019-11922: Fixed race condition in one-pass compression
functions that could allow out of bounds write (boo#1142941).

Non-security issues fixed :

&#9; - Added --[no-]compress-literals CLI flag to enable or disable
literal compression.

  - Added new --rsyncable mode.

  - Added handling of -f flag to zstdgrep.

  - Added CPU load indicator for each file on -vv mode.

  - Changed --no-progress flag to preserve the final
    summary.

  - Added new command --adapt for compressed network piping
    of data adjusted to the perceived network conditions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142941"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zstd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zstd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zstd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zstd-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/13");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libzstd-devel-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzstd-devel-static-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzstd1-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzstd1-debuginfo-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zstd-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zstd-debuginfo-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zstd-debugsource-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libzstd1-32bit-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libzstd1-32bit-debuginfo-1.4.2-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzstd-devel / libzstd-devel-static / libzstd1 / etc");
}
