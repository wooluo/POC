#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1533.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125808);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/11 15:17:49");

  script_cve_id("CVE-2018-5740", "CVE-2018-5743", "CVE-2018-5745", "CVE-2019-6465");

  script_name(english:"openSUSE Security Update : bind (openSUSE-2019-1533)");
  script_summary(english:"Check for the openSUSE-2019-1533 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bind fixes the following issues :

Security issues fixed :

  - CVE-2019-6465: Fixed an issue where controls for zone
    transfers may not be properly applied to Dynamically
    Loadable Zones (bsc#1126069).

  - CVE-2018-5745: Fixed a denial of service vulnerability
    if a trust anchor rolls over to an unsupported key
    algorithm when using managed-keys (bsc#1126068).

  - CVE-2018-5743: Fixed a denial of service vulnerability
    which could be caused by to many simultaneous TCP
    connections (bsc#1133185).

  - CVE-2018-5740: Fixed a denial of service vulnerability
    in the 'deny-answer-aliases' feature (bsc#1104129).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133185"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-160-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-160-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-160-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns169-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns169-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns169-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs160-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs160-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs160-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc166");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc166-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc166-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc166-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc160-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc160-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc160-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg160-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg160-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg160-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblwres160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblwres160-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblwres160-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblwres160-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/11");
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

if ( rpm_check(release:"SUSE15.0", reference:"bind-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-chrootenv-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-debugsource-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-devel-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-lwresd-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-lwresd-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-utils-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bind-utils-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libbind9-160-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libbind9-160-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libdns169-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libdns169-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libirs-devel-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libirs160-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libirs160-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libisc166-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libisc166-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libisccc160-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libisccc160-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libisccfg160-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libisccfg160-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblwres160-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblwres160-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-bind-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"bind-devel-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libbind9-160-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libbind9-160-32bit-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libdns169-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libdns169-32bit-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libirs160-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libirs160-32bit-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libisc166-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libisc166-32bit-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libisccc160-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libisccc160-32bit-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libisccfg160-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libisccfg160-32bit-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"liblwres160-32bit-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"liblwres160-32bit-debuginfo-9.11.2-lp150.8.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-chrootenv-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-debugsource-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-devel-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-lwresd-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-lwresd-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-utils-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"bind-utils-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libbind9-160-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libbind9-160-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdns169-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdns169-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libirs-devel-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libirs160-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libirs160-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libisc166-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libisc166-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libisccc160-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libisccc160-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libisccfg160-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libisccfg160-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblwres160-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblwres160-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-bind-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"bind-devel-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libbind9-160-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libbind9-160-32bit-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdns169-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdns169-32bit-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libirs160-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libirs160-32bit-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libisc166-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libisc166-32bit-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libisccc160-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libisccc160-32bit-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libisccfg160-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libisccfg160-32bit-debuginfo-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liblwres160-32bit-9.11.2-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"liblwres160-32bit-debuginfo-9.11.2-lp151.11.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chrootenv / bind-debuginfo / bind-debugsource / etc");
}
