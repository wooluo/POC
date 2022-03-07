#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1547.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125844);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/12 10:41:31");

  script_cve_id("CVE-2018-0734", "CVE-2018-11763", "CVE-2018-11784", "CVE-2018-3309", "CVE-2019-2446", "CVE-2019-2448", "CVE-2019-2450", "CVE-2019-2451", "CVE-2019-2500", "CVE-2019-2501", "CVE-2019-2504", "CVE-2019-2505", "CVE-2019-2506", "CVE-2019-2508", "CVE-2019-2509", "CVE-2019-2511", "CVE-2019-2520", "CVE-2019-2521", "CVE-2019-2522", "CVE-2019-2523", "CVE-2019-2524", "CVE-2019-2525", "CVE-2019-2526", "CVE-2019-2527", "CVE-2019-2548", "CVE-2019-2552", "CVE-2019-2553", "CVE-2019-2554", "CVE-2019-2555", "CVE-2019-2556");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2019-1547)");
  script_summary(english:"Check for the openSUSE-2019-1547 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox to version 5.2.24 fixes the following
issues :

Multiple security issues fixed :

CVE-2019-2500, CVE-2019-2524, CVE-2019-2552, CVE-2018-3309,
CVE-2019-2520 CVE-2019-2521, CVE-2019-2522, CVE-2019-2523,
CVE-2019-2526, CVE-2019-2548 CVE-2018-11763, CVE-2019-2511,
CVE-2019-2508, CVE-2019-2509, CVE-2019-2527 CVE-2019-2450,
CVE-2019-2451, CVE-2019-2555, CVE-2019-2554, CVE-2019-2556
CVE-2018-11784, CVE-2018-0734, CVE-2019-2525, CVE-2019-2446,
CVE-2019-2448 CVE-2019-2501, CVE-2019-2504, CVE-2019-2505,
CVE-2019-2506, and CVE-2019-2553 (bsc#1122212).

Other issues fixed :

  - Linux Additions: fix for building vboxvideo on EL 7.6
    standard kernel, contributed by Robert Conde

  - USB: fixed a problem causing failures attaching
    SuperSpeed devices which report USB version 3.1 (rather
    than 3.0) on Windows hosts

  - Audio: added support for surround speaker setups used by
    Windows 10 Build 1809

  - Linux hosts: fixed conflict between Debian and Oracle
    build desktop files 

  - Linux guests: fixed building drivers on SLES 12.4

  - Linux guests: fixed building shared folder driver with
    older kernels"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122212"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/12");
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

if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-debuginfo-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debuginfo-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debugsource-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-devel-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-desktop-icons-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-5.2.24_k4.12.14_lp150.12.61-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-debuginfo-5.2.24_k4.12.14_lp150.12.61-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-source-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-debuginfo-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-debuginfo-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-5.2.24_k4.12.14_lp150.12.61-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-debuginfo-5.2.24_k4.12.14_lp150.12.61-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-source-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-debuginfo-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-vnc-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-5.2.24-lp150.4.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-debuginfo-5.2.24-lp150.4.33.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-virtualbox / python3-virtualbox-debuginfo / virtualbox / etc");
}
