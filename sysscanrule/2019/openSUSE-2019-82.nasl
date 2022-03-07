#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-82.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(121340);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2019-6442", "CVE-2019-6443", "CVE-2019-6444", "CVE-2019-6445");

  script_name(english:"openSUSE Security Update : ntpsec (openSUSE-2019-82)");
  script_summary(english:"Check for the openSUSE-2019-82 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ntpsec to version 1.1.3 fixes the following issues :

Security issues fixed :

  - CVE-2019-6442: Fixed a out of bounds write via a
    malformed config request (boo#1122132)

  - CVE-2019-6443: Fixed a stack-based buffer over-read in
    the ctl_getitem function (boo#1122144)

  - CVE-2019-6444: Fixed a stack-based buffer over-read in
    the process_control function (boo#1122134)

  - CVE-2019-6445: Fixed a NULL pointer dereference in the
    ctl_getitem function (boo#1122131)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122144"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ntpsec packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntpsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntpsec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntpsec-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntpsec-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/24");
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

if ( rpm_check(release:"SUSE15.0", reference:"ntpsec-1.1.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ntpsec-debuginfo-1.1.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ntpsec-debugsource-1.1.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ntpsec-utils-1.1.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-ntp-1.1.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-ntp-debuginfo-1.1.3-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntpsec / ntpsec-debuginfo / ntpsec-debugsource / ntpsec-utils / etc");
}
