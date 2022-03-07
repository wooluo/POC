#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1162.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(123817);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/29 10:00:59");

  script_cve_id("CVE-2018-18335", "CVE-2018-18356", "CVE-2018-18506", "CVE-2018-18509", "CVE-2019-5785", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9801", "CVE-2019-9810", "CVE-2019-9813");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2019-1162)");
  script_summary(english:"Check for the openSUSE-2019-1162 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaThunderbird to version 60.5.1 fixes the
following issues :

Security issues fixed :

  - Update to MozillaThunderbird 60.6.1 (bsc#1130262) :

  - CVE-2019-9813: Fixed Ionmonkey type confusion with
    __proto__ mutations

  - CVE-2019-9810: Fixed IonMonkey MArraySlice incorrect
    alias information

  - Update to MozillaThunderbird 60.6 (bsc#1129821) :

  - CVE-2018-18506: Fixed an issue with Proxy
    Auto-Configuration file 

  - CVE-2019-9801: Fixed an issue which could allow Windows
    programs to be exposed to web content

  - CVE-2019-9788: Fixed multiple memory safety bugs

  - CVE-2019-9790: Fixed a Use-after-free vulnerability when
    removing in-use DOM elements

  - CVE-2019-9791: Fixed an incorrect Type inference for
    constructors entered through on-stack replacement with
    IonMonkey

  - CVE-2019-9792: Fixed an issue where IonMonkey leaks
    JS_OPTIMIZED_OUT magic value to script

  - CVE-2019-9793: Fixed multiple improper bounds checks
    when Spectre mitigations are disabled

  - CVE-2019-9794: Fixed an issue where command line
    arguments not discarded during execution

  - CVE-2019-9795: Fixed a Type-confusion vulnerability in
    IonMonkey JIT compiler

  - CVE-2019-9796: Fixed a Use-after-free vulnerability in
    SMIL animation controller

  - Update to MozillaThunderbird 60.5.1 (bsc#1125330) :

  - CVE-2018-18356: Fixed a use-after-free vulnerability in
    the Skia library which can occur when creating a path,
    leading to a potentially exploitable crash.

  - CVE-2019-5785: Fixed an integer overflow vulnerability
    in the Skia library which can occur after specific
    transform operations, leading to a potentially
    exploitable crash.

  - CVE-2018-18335: Fixed a buffer overflow vulnerability in
    the Skia library which can occur with Canvas 2D
    acceleration on macOS. This issue was addressed by
    disabling Canvas 2D acceleration in Firefox ESR. Note:
    this does not affect other versions and platforms where
    Canvas 2D acceleration is already disabled by default.

  - CVE-2018-18509: Fixed a flaw which during verification
    of certain S/MIME signatures showing mistakenly that
    emails bring a valid sugnature. Release notes:
    https://www.mozilla.org/en-US/security/advisories/mfsa20
    19-12/
    https://www.mozilla.org/en-US/security/advisories/mfsa20
    19-11/
    https://www.mozilla.org/en-US/security/advisories/mfsa20
    19-06/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-06/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-11/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-12/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/08");
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

if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-60.6.1-lp150.3.37.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-buildsymbols-60.6.1-lp150.3.37.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debuginfo-60.6.1-lp150.3.37.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debugsource-60.6.1-lp150.3.37.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-common-60.6.1-lp150.3.37.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-other-60.6.1-lp150.3.37.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
