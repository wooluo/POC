#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1912.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128004);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2766", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2842", "CVE-2019-7317");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2019-1912)");
  script_summary(english:"Check for the openSUSE-2019-1912 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk to version 8u222 fixes the
following issues :

Security issues fixed :

  - CVE-2019-2745: Improved ECC Implementation
    (bsc#1141784).

  - CVE-2019-2762: Exceptional throw cases (bsc#1141782).

  - CVE-2019-2766: Improve file protocol handling
    (bsc#1141789).

  - CVE-2019-2769: Better copies of CopiesList
    (bsc#1141783).

  - CVE-2019-2786: More limited privilege usage
    (bsc#1141787).

  - CVE-2019-2816: Normalize normalization (bsc#1141785).

  - CVE-2019-2842: Extended AES support (bsc#1141786).

  - CVE-2019-7317: Improve PNG support (bsc#1141780).

  - Certificate validation improvements

Non-security issue fixed :

  - Fixed an issue where the installation failed when the
    manpages are not present (bsc#1115375)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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

if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-accessibility-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debugsource-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-javadoc-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-src-1.8.0.222-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-accessibility-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-demo-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-devel-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-headless-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-javadoc-1.8.0.222-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-src-1.8.0.222-lp151.2.3.1") ) flag++;

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
