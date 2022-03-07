#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1217.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124108);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/17  9:22:56");

  script_cve_id("CVE-2019-3816", "CVE-2019-3833");

  script_name(english:"openSUSE Security Update : openwsman (openSUSE-2019-1217)");
  script_summary(english:"Check for the openSUSE-2019-1217 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openwsman fixes the following issues :

Security issues fixed :

  - CVE-2019-3816: Fixed a vulnerability in openwsmand
    deamon which could lead to arbitary file disclosure
    (bsc#1122623).

  - CVE-2019-3833: Fixed a vulnerability in
    process_connection() which could allow an attacker to
    trigger an infinite loop which leads to Denial of
    Service (bsc#1122623).

Other issues addressed :

  - Directory listing without authentication fixed
    (bsc#1092206).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122623"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openwsman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman_clientpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman_clientpp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman_clientpp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-server-plugin-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-server-plugin-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:winrs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libwsman-devel-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwsman3-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwsman3-debuginfo-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwsman_clientpp-devel-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwsman_clientpp1-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwsman_clientpp1-debuginfo-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-debugsource-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-java-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-perl-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-perl-debuginfo-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-python-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-python-debuginfo-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-ruby-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-ruby-debuginfo-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-server-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-server-debuginfo-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-server-plugin-ruby-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openwsman-server-plugin-ruby-debuginfo-2.6.7-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"winrs-2.6.7-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwsman-devel / libwsman3 / libwsman3-debuginfo / etc");
}
