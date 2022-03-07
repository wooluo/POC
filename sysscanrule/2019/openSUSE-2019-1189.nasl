#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1189.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124016);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/12  9:50:26");

  script_cve_id("CVE-2019-9211");

  script_name(english:"openSUSE Security Update : pspp (openSUSE-2019-1189)");
  script_summary(english:"Check for the openSUSE-2019-1189 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pspp fixes the following issues :

  - CVE-2019-9211: Handle a reachable assertion in
    write_long_string_missing_values() in libdata.a that
    could have lead to denial of service. (boo#1127343).

  - Remove excessive -n argument to %build, and excessive
    %defattr lines."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127343"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pspp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"pspp-1.2.0-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pspp-debuginfo-1.2.0-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pspp-debugsource-1.2.0-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pspp-devel-1.2.0-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-1.2.0-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-debuginfo-1.2.0-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-debugsource-1.2.0-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-devel-1.2.0-14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pspp / pspp-debuginfo / pspp-debugsource / pspp-devel");
}
