#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1797.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126980);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/24  9:40:16");

  script_cve_id("CVE-2019-7314", "CVE-2019-9215");

  script_name(english:"openSUSE Security Update : live555 (openSUSE-2019-1797)");
  script_summary(english:"Check for the openSUSE-2019-1797 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for live555 fixes the following issues :

  - CVE-2019-9215: Malformed headers could have lead to
    invalid memory access in the parseAuthorizationHeader
    function. (boo#1127341)

  - CVE-2019-7314: Mishandled termination of an RTSP stream
    after RTP/RTCP-over-RTSP has been set up could have lead
    to a Use-After-Free error causing the RTSP server to
    crash or possibly have unspecified other impact.
    (boo#1124159)

  - Update to version 2019.06.28, 

  - Convert to dynamic libraries (boo#1121995) :

  + Use make ilinux-with-shared-libraries: build the dynamic
    libs instead of the static one.

  + Use make install instead of a manual file copy script:
    this also reveals that we missed quite a bit of code to
    be installed before.

  + Split out shared library packages according the SLPP.

  - Use FAT LTO objects in order to provide proper static
    library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127341"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected live555 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libBasicUsageEnvironment1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libBasicUsageEnvironment1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libUsageEnvironment3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libUsageEnvironment3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgroupsock8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgroupsock8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libliveMedia66");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libliveMedia66-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:live555");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:live555-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:live555-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:live555-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
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
if (release !~ "^(SUSE15\.0|SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libBasicUsageEnvironment1-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libBasicUsageEnvironment1-debuginfo-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libUsageEnvironment3-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libUsageEnvironment3-debuginfo-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgroupsock8-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgroupsock8-debuginfo-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libliveMedia66-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libliveMedia66-debuginfo-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"live555-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"live555-debuginfo-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"live555-debugsource-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"live555-devel-2019.06.28-lp150.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libBasicUsageEnvironment1-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libBasicUsageEnvironment1-debuginfo-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libUsageEnvironment3-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libUsageEnvironment3-debuginfo-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgroupsock8-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgroupsock8-debuginfo-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libliveMedia66-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libliveMedia66-debuginfo-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"live555-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"live555-debuginfo-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"live555-debugsource-2019.06.28-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"live555-devel-2019.06.28-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libBasicUsageEnvironment1 / libBasicUsageEnvironment1-debuginfo / etc");
}
