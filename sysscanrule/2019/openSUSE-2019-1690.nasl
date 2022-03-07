#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1690.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126491);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/05  9:53:32");

  script_cve_id("CVE-2019-13045");

  script_name(english:"openSUSE Security Update : irssi (openSUSE-2019-1690)");
  script_summary(english:"Check for the openSUSE-2019-1690 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for irssi fixes the following issues :

irssi was updated to 1.1.3 :

  - CVE-2019-13045: Fix a use after free issue when sending
    the SASL login on (automatic and manual) reconnects
    (#1055, #1058) (boo#1139802)

  - Fix regression of #779 where autolog_ignore_targets
    would not matching itemless windows anymore (#1012,
    #1013)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139802"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected irssi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");
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

if ( rpm_check(release:"SUSE15.0", reference:"irssi-1.1.3-lp150.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"irssi-debuginfo-1.1.3-lp150.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"irssi-debugsource-1.1.3-lp150.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"irssi-devel-1.1.3-lp150.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"irssi-1.1.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"irssi-debuginfo-1.1.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"irssi-debugsource-1.1.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"irssi-devel-1.1.3-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi / irssi-debuginfo / irssi-debugsource / irssi-devel");
}
