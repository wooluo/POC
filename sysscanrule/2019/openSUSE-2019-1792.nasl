#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1792.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126976);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/24  9:40:16");

  script_cve_id("CVE-2019-12904");

  script_name(english:"openSUSE Security Update : libgcrypt (openSUSE-2019-1792)");
  script_summary(english:"Check for the openSUSE-2019-1792 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libgcrypt fixes the following issues :

Security issues fixed :

  - CVE-2019-12904: The C implementation of AES is
    vulnerable to a flush-and-reload side-channel attack
    because physical addresses are available to other
    processes. (The C implementation is used on platforms
    where an assembly-language implementation is
    unavailable.) (bsc#1138939)

Other bugfixes :

  - Don't run full FIPS self-tests from constructor
    (bsc#1097073)

  - Skip all the self-tests except for binary integrity when
    called from the constructor (bsc#1097073)

  - Enforce the minimal RSA keygen size in fips mode
    (bsc#1125740)

  - avoid executing some tests twice.

  - Fixed a race condition in initialization.

  - Fixed env-script-interpreter in cavs_driver.pl

  - Fixed redundant fips tests in some situations causing
    failure to boot in fips mode. (bsc#1097073)

This helps during booting of the system in FIPS mode with insufficient
entropy.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138939"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/24");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-cavs-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-cavs-debuginfo-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-debugsource-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-devel-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-devel-debuginfo-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt20-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt20-debuginfo-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt20-hmac-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt-devel-32bit-debuginfo-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt20-32bit-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt20-32bit-debuginfo-1.8.2-lp150.5.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt20-hmac-32bit-1.8.2-lp150.5.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt-cavs / libgcrypt-cavs-debuginfo / libgcrypt-debugsource / etc");
}