#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1751.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126892);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-10153");

  script_name(english:"openSUSE Security Update : fence-agents (openSUSE-2019-1751)");
  script_summary(english:"Check for the openSUSE-2019-1751 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for fence-agents version 4.4.0 fixes the following 
issues :

Security issue fixed :

  - CVE-2019-10153: Fixed a denial of service via guest VM
    comments (bsc#1137314).

Non-security issue fixed :

  - Added aliyun fence agent (bsc#1139913).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/320898"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fence-agents packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fence-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fence-agents-amt_ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fence-agents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fence-agents-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fence-agents-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"fence-agents-4.4.0+git.1558595666.5f79f9e9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fence-agents-amt_ws-4.4.0+git.1558595666.5f79f9e9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fence-agents-debuginfo-4.4.0+git.1558595666.5f79f9e9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fence-agents-debugsource-4.4.0+git.1558595666.5f79f9e9-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fence-agents-devel-4.4.0+git.1558595666.5f79f9e9-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fence-agents / fence-agents-amt_ws / fence-agents-debuginfo / etc");
}
