#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1814.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127734);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-0734", "CVE-2018-11763", "CVE-2018-11784", "CVE-2018-3288", "CVE-2018-3289", "CVE-2018-3290", "CVE-2018-3291", "CVE-2018-3292", "CVE-2018-3293", "CVE-2018-3294", "CVE-2018-3295", "CVE-2018-3296", "CVE-2018-3297", "CVE-2018-3298", "CVE-2019-1543", "CVE-2019-2446", "CVE-2019-2448", "CVE-2019-2450", "CVE-2019-2451", "CVE-2019-2508", "CVE-2019-2509", "CVE-2019-2511", "CVE-2019-2525", "CVE-2019-2527", "CVE-2019-2554", "CVE-2019-2555", "CVE-2019-2556", "CVE-2019-2574", "CVE-2019-2656", "CVE-2019-2657", "CVE-2019-2678", "CVE-2019-2679", "CVE-2019-2680", "CVE-2019-2690", "CVE-2019-2696", "CVE-2019-2703", "CVE-2019-2721", "CVE-2019-2722", "CVE-2019-2723", "CVE-2019-2848", "CVE-2019-2850", "CVE-2019-2859", "CVE-2019-2863", "CVE-2019-2864", "CVE-2019-2865", "CVE-2019-2866", "CVE-2019-2867", "CVE-2019-2873", "CVE-2019-2874", "CVE-2019-2875", "CVE-2019-2876", "CVE-2019-2877");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2019-1814)");
  script_summary(english:"Check for the openSUSE-2019-1814 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox to version 6.0.10 fixes the following
issues :

Security issues fixed :

  - CVE-2019-2859 CVE-2019-2867 CVE-2019-2866 CVE-2019-2864
    CVE-2019-2865 CVE-2019-1543 CVE-2019-2863 CVE-2019-2848
    CVE-2019-2877 CVE-2019-2873 CVE-2019-2874 CVE-2019-2875
    CVE-2019-2876 CVE-2019-2850 (boo#1141801)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141801"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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

if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-debuginfo-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debuginfo-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debugsource-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-devel-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-desktop-icons-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-6.0.10_k4.12.14_lp150.12.67-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-debuginfo-6.0.10_k4.12.14_lp150.12.67-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-source-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-debuginfo-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-debuginfo-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-6.0.10_k4.12.14_lp150.12.67-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-debuginfo-6.0.10_k4.12.14_lp150.12.67-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-source-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-debuginfo-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-vnc-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-debuginfo-6.0.10-lp150.4.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-virtualbox-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-virtualbox-debuginfo-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-debuginfo-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-debugsource-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-devel-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-desktop-icons-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-kmp-default-6.0.10_k4.12.14_lp151.28.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-kmp-default-debuginfo-6.0.10_k4.12.14_lp151.28.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-source-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-tools-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-tools-debuginfo-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-x11-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-x11-debuginfo-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-host-kmp-default-6.0.10_k4.12.14_lp151.28.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-host-kmp-default-debuginfo-6.0.10_k4.12.14_lp151.28.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-host-source-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-qt-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-qt-debuginfo-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-vnc-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-websrv-6.0.10-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-websrv-debuginfo-6.0.10-lp151.2.6.1") ) flag++;

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
