#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-261.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122497);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/28 10:07:15");

  script_cve_id("CVE-2019-3827");

  script_name(english:"openSUSE Security Update : gvfs (openSUSE-2019-261)");
  script_summary(english:"Check for the openSUSE-2019-261 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gvfs fixes the following issues :

Security vulnerability fixed :

  - CVE-2019-3827: Fixed an issue whereby an unprivileged
    user was not prompted to give a password when acessing
    root owned files. (bsc#1125084)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125084"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gvfs packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-backend-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-backend-afc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-backend-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-backend-samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-backends");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-backends-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvfs-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");
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

if ( rpm_check(release:"SUSE15.0", reference:"gvfs-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-backend-afc-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-backend-afc-debuginfo-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-backend-samba-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-backend-samba-debuginfo-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-backends-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-backends-debuginfo-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-debuginfo-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-debugsource-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-devel-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-fuse-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-fuse-debuginfo-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvfs-lang-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gvfs-32bit-1.34.2.1-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"gvfs-32bit-debuginfo-1.34.2.1-lp150.3.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs / gvfs-32bit / gvfs-32bit-debuginfo / gvfs-backend-afc / etc");
}
