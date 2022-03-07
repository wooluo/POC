#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-346.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122943);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/19 11:02:10");

  script_cve_id("CVE-2018-11212", "CVE-2019-2422");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2019-346)");
  script_summary(english:"Check for the openSUSE-2019-346 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk to version jdk8u201 (icedtea
3.11.0) fixes the following issues: &#9; Security issues fixed :

  - CVE-2019-2422: Fixed a memory disclosure in
    FileChannelImpl (bsc#1122293).

  - CVE-2018-11212: Fixed an issue in alloc_sarray function
    in jmemmgr.c (bsc#1122299).&#9;

Complete list of changes:
https://mail.openjdk.java.net/pipermail/distro-pkg-dev/2019-March/0412
23.html 

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122299"
  );
  # https://mail.openjdk.java.net/pipermail/distro-pkg-dev/2019-March/041223.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/19");
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

if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-accessibility-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debugsource-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-javadoc-1.8.0.201-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-src-1.8.0.201-lp150.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
