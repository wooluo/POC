#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1965.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128046);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/21  9:43:47");

  script_cve_id("CVE-2019-13619");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2019-1965)");
  script_summary(english:"Check for the openSUSE-2019-1965 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark to version 2.4.16 fixes the following 
issues :

Security issue fixed :

  - CVE-2019-13619: ASN.1 BER and related dissectors crash
    (bsc#1141980).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141980"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwscodecs1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/21");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libwireshark9-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwireshark9-debuginfo-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwiretap7-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwiretap7-debuginfo-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwscodecs1-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwscodecs1-debuginfo-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwsutil8-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwsutil8-debuginfo-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wireshark-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wireshark-debuginfo-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wireshark-debugsource-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wireshark-devel-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wireshark-ui-qt-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"wireshark-ui-qt-debuginfo-2.4.16-lp150.2.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwireshark9-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwireshark9-debuginfo-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwiretap7-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwiretap7-debuginfo-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwscodecs1-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwscodecs1-debuginfo-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwsutil8-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwsutil8-debuginfo-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-debuginfo-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-debugsource-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-devel-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-ui-qt-2.4.16-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-ui-qt-debuginfo-2.4.16-lp151.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwireshark9 / libwireshark9-debuginfo / libwiretap7 / etc");
}
