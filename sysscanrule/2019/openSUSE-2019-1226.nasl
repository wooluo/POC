#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1226.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124147);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/18  9:41:09");

  script_cve_id("CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967", "CVE-2019-6778", "CVE-2019-9824");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2019-1226)");
  script_summary(english:"Check for the openSUSE-2019-1226 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

Security issues fixed :

  - CVE-2018-19967: Fixed HLE constructs that allowed guests
    to lock up the host, resulting in a Denial of Service
    (DoS). (XSA-282) (bsc#1114988)

  - CVE-2019-6778: Fixed a heap buffer overflow in tcp_emu()
    found in slirp (bsc#1123157).

  - Fixed an issue which could allow malicious or buggy
    guests with passed through PCI devices to be able to
    escalate their privileges, crash the host, or access
    data belonging to other guests. Additionally memory
    leaks were also possible (bsc#1126140).

  - Fixed a race condition issue which could allow malicious
    PV guests to escalate their privilege to that of the
    hypervisor (bsc#1126141).

  - Fixed an issue which could allow a malicious
    unprivileged guest userspace process to escalate its
    privilege to that of other userspace processes in the
    same guest and potentially thereby to that of the guest
    operating system (bsc#1126201).

  - CVE-2019-9824: Fixed an information leak in SLiRP
    networking implementation which could allow a
    user/process to read uninitialised stack memory contents
    (bsc#1129623).

  - CVE-2018-19961 CVE-2018-19962: Fixed insufficient TLB
    flushing / improper large page mappings with AMD IOMMUs
    (XSA-275)(bsc#1115040).

  - CVE-2018-19965: Fixed denial of service issue from
    attempting to use INVPCID with a non-canonical addresses
    (XSA-279)(bsc#1115045).

  - CVE-2018-19966: Fixed issue introduced by XSA-240 that
    could have caused conflicts with shadow paging
    (XSA-280)(bsc#1115047).

  - Fixed an issue which could allow malicious PV guests may
    cause a host crash or gain access to data pertaining to
    other guests.Additionally, vulnerable configurations are
    likely to be unstable even in the absence of an attack
    (bsc#1126198).

  - Fixed multiple access violations introduced by
    XENMEM_exchange hypercall which could allow a single PV
    guest to leak arbitrary amounts of memory, leading to a
    denial of service (bsc#1126192).

  - Fixed an issue which could allow malicious 64bit PV
    guests to cause a host crash (bsc#1127400).

  - Fixed an issue which could allow malicious or buggy x86
    PV guest kernels to mount a Denial of Service attack
    affecting the whole system (bsc#1126197).

  - Fixed an issue which could allow an untrusted PV domain
    with access to a physical device to DMA into its own
    pagetables leading to privilege escalation
    (bsc#1126195).

  - Fixed an issue which could allow a malicious or buggy
    x86 PV guest kernels can mount a Denial of Service
    attack affecting the whole system (bsc#1126196).

Other issues addressed :

  - Upstream bug fixes (bsc#1027519)

  - Fixed an issue where live migrations were failing when
    spectre was enabled on xen boot cmdline (bsc#1116380).

  - Fixed an issue where setup of grant_tables and other
    variables may fail (bsc#1126325).

  - Fixed a building issue (bsc#1119161).

  - Fixed an issue where xpti=no-dom0 was not working as
    expected (bsc#1105528).

  - Packages should no longer use /var/adm/fillup-templates
    (bsc#1069468). 

  - Added Xen cmdline option 'suse_vtsc_tolerance' to avoid
    TSC emulation for HVM domUs (bsc#1026236).

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129623"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");
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

if ( rpm_check(release:"SUSE42.3", reference:"xen-debugsource-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-devel-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-debuginfo-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-debuginfo-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xen-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xen-doc-html-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xen-libs-32bit-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xen-tools-4.9.4_02-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xen-tools-debuginfo-4.9.4_02-37.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen-debugsource / xen-devel / xen-libs-32bit / xen-libs / etc");
}
