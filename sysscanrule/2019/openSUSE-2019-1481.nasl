#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1481.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125668);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/05  9:33:19");

  script_cve_id("CVE-2015-1331", "CVE-2015-1334", "CVE-2015-1335", "CVE-2017-5985", "CVE-2018-6556", "CVE-2019-5736");

  script_name(english:"openSUSE Security Update : lxc / lxcfs (openSUSE-2019-1481)");
  script_summary(english:"Check for the openSUSE-2019-1481 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for lxc, lxcfs to version 3.1.0 fixes the following 
issues :

Security issues fixed :

  - CVE-2019-5736: Fixed a container breakout vulnerability
    (boo#1122185).

  - CVE-2018-6556: Enable setuid bit on lxc-user-nic
    (boo#988348).

Non-security issues fixed :

  - Update to LXC 3.1.0. The changelog is far too long to
    include here, please look at
    https://linuxcontainers.org/. (boo#1131762)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://linuxcontainers.org/."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lxc / lxcfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxcfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxcfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxcfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxcfs-hooks-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_cgfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_cgfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/03");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"lxc-bash-completion-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lxcfs-3.0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lxcfs-debuginfo-3.0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lxcfs-debugsource-3.0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lxcfs-hooks-lxc-3.0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"liblxc-devel-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"liblxc1-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"liblxc1-debuginfo-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"lxc-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"lxc-debuginfo-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"lxc-debugsource-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pam_cgfs-3.1.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pam_cgfs-debuginfo-3.1.0-24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lxcfs / lxcfs-debuginfo / lxcfs-debugsource / lxcfs-hooks-lxc / etc");
}
