#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1264.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124291);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/25  9:51:46");

  script_cve_id("CVE-2019-6438");

  script_name(english:"openSUSE Security Update : slurm (openSUSE-2019-1264)");
  script_summary(english:"Check for the openSUSE-2019-1264 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for slurm to version 17.11.13 fixes the following issues :

Security issue fixed :

  - CVE-2019-6438: Fixed a heap overflow on 32-bit systems
    in xmalloc (bsc#1123304).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123304"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected slurm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpmi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libslurm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libslurm32-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-openlava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-seff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sjstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/25");
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

if ( rpm_check(release:"SUSE15.0", reference:"libpmi0-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpmi0-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libslurm32-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libslurm32-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-slurm-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-slurm-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-auth-none-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-auth-none-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-config-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-debugsource-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-devel-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-lua-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-lua-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-munge-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-munge-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-node-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-node-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-openlava-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-pam_slurm-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-pam_slurm-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-plugins-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-plugins-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-seff-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-sjstat-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-slurmdbd-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-slurmdbd-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-sql-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-sql-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-sview-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-sview-debuginfo-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-torque-17.11.13-lp150.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"slurm-torque-debuginfo-17.11.13-lp150.5.20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpmi0 / libpmi0-debuginfo / libslurm32 / libslurm32-debuginfo / etc");
}
