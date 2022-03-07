#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1916.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128008);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2766", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2818", "CVE-2019-2821", "CVE-2019-7317");

  script_name(english:"openSUSE Security Update : java-11-openjdk (openSUSE-2019-1916)");
  script_summary(english:"Check for the openSUSE-2019-1916 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-11-openjdk to version jdk-11.0.4+11 fixes the
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

  - CVE-2019-7317: Improve PNG support options
    (bsc#1141780).

  - CVE-2019-2818: Better Poly1305 support (bsc#1141788).

  - CVE-2019-2816: Normalize normalization (bsc#1141785).

  - CVE-2019-2821: Improve TLS negotiation (bsc#1141781).

  - Certificate validation improvements

Non-security issues fixed :

  - Do not fail installation when the manpages are not
    present (bsc#1115375)

  - Backport upstream fix for JDK-8208602: Cannot read PEM
    X.509 cert if there is whitespace after the header or
    footer (bsc#1140461)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141781"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-11-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-src");
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

if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-javadoc-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-accessibility-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-accessibility-debuginfo-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-debuginfo-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-debugsource-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-demo-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-devel-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-headless-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-jmods-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"java-11-openjdk-src-11.0.4.0-lp150.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-accessibility-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-accessibility-debuginfo-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-debuginfo-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-debugsource-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-demo-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-devel-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-headless-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-javadoc-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-jmods-11.0.4.0-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-src-11.0.4.0-lp151.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-accessibility / etc");
}
