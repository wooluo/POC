#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1403.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125242);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/17  9:44:15");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2019-1403) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Check for the openSUSE-2019-1403 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

Four new speculative execution information leak issues have been
identified in Intel CPUs. (bsc#1111331)

  - CVE-2018-12126: Microarchitectural Store Buffer Data
    Sampling (MSBDS)

  - CVE-2018-12127: Microarchitectural Fill Buffer Data
    Sampling (MFBDS)

  - CVE-2018-12130: Microarchitectural Load Port Data
    Samling (MLPDS)

  - CVE-2019-11091: Microarchitectural Data Sampling
    Uncacheable Memory (MDSUM)

These updates contain the XEN Hypervisor adjustments, that additionaly
also use CPU Microcode updates.

The mitigation can be controlled via the 'mds' commandline option, see
the documentation.

For more information on this set of vulnerabilities, check out
https://www.suse.com/support/kb/doc/?id=7023736

Other fixes :

  - Added code to change LIBXL_HOTPLUG_TIMEOUT at runtime.

    The included README has details about the impact of this
    change (bsc#1120095)

  - Fixes in Live migrating PV domUs

    An earlier change broke live migration of PV domUs
    without a device model. The migration would stall for 10
    seconds while the domU was paused, which caused network
    connections to drop. Fix this by tracking the need for a
    device model within libxl. (bsc#1079730, bsc#1098403,
    bsc#1111025)

  - Libvirt segfault when crash triggered on top of HVM
    guest (bsc#1120067)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/support/kb/doc/?id=7023736"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"xen-debugsource-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-devel-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-debuginfo-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-debuginfo-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-doc-html-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-debuginfo-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-4.10.3_04-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.10.3_04-lp150.2.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-debugsource / xen-devel / xen-doc-html / xen-libs / etc");
}
