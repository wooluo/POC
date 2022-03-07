#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1590.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126061);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/20 11:24:23");

  script_cve_id("CVE-2017-7607", "CVE-2017-7608", "CVE-2017-7609", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613", "CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7150", "CVE-2019-7665");

  script_name(english:"openSUSE Security Update : elfutils (openSUSE-2019-1590)");
  script_summary(english:"Check for the openSUSE-2019-1590 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for elfutils fixes the following issues :

Security issues fixed :

  - CVE-2017-7607: Fixed a heap-based buffer overflow in
    handle_gnu_hash (bsc#1033084)

  - CVE-2017-7608: Fixed a heap-based buffer overflow in
    ebl_object_note_type_name() (bsc#1033085)

  - CVE-2017-7609: Fixed a memory allocation failure in
    __libelf_decompress (bsc#1033086)

  - CVE-2017-7610: Fixed a heap-based buffer overflow in
    check_group (bsc#1033087)

  - CVE-2017-7611: Fixed a denial of service via a crafted
    ELF file (bsc#1033088)

  - CVE-2017-7612: Fixed a denial of service in
    check_sysv_hash() via a crafted ELF file (bsc#1033089)

  - CVE-2017-7613: Fixed denial of service caused by the
    missing validation of the number of sections and the
    number of segments in a crafted ELF file (bsc#1033090)

  - CVE-2018-16062: Fixed a heap-buffer overflow in
    /elfutils/libdw/dwarf_getaranges.c:156 (bsc#1106390)

  - CVE-2018-16402: Fixed a denial of service/double free on
    an attempt to decompress the same section twice
    (bsc#1107066)

  - CVE-2018-16403: Fixed a heap buffer overflow in readelf
    (bsc#1107067)

  - CVE-2018-18310: Fixed an invalid address read problem in
    dwfl_segment_report_module.c (bsc#1111973)

  - CVE-2018-18520: Fixed bad handling of ar files inside
    are files (bsc#1112726)

  - CVE-2018-18521: Fixed a denial of service
    vulnerabilities in the function arlib_add_symbols() used
    by eu-ranlib (bsc#1112723)

  - CVE-2019-7150: dwfl_segment_report_module doesn't check
    whether the dyn data read from core file is truncated
    (bsc#1123685)

  - CVE-2019-7665: NT_PLATFORM core file note should be a
    zero terminated string (bsc#1125007)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125007"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elfutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:elfutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:elfutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:elfutils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl-plugins-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl-plugins-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/20");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"elfutils-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"elfutils-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"elfutils-debugsource-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"elfutils-lang-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libasm-devel-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libasm1-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libasm1-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libdw-devel-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libdw1-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libdw1-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libebl-devel-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libebl-plugins-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libebl-plugins-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libelf-devel-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libelf1-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libelf1-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libasm1-32bit-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libasm1-32bit-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libdw1-32bit-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libdw1-32bit-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libebl-plugins-32bit-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libebl-plugins-32bit-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libelf-devel-32bit-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libelf1-32bit-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libelf1-32bit-debuginfo-0.168-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"elfutils-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"elfutils-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"elfutils-debugsource-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"elfutils-lang-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasm-devel-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasm1-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libasm1-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdw-devel-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdw1-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdw1-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libebl-devel-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libebl-plugins-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libebl-plugins-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libelf-devel-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libelf1-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libelf1-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libasm1-32bit-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libasm1-32bit-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdw1-32bit-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdw1-32bit-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libebl-plugins-32bit-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libebl-plugins-32bit-debuginfo-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libelf-devel-32bit-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libelf1-32bit-0.168-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libelf1-32bit-debuginfo-0.168-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils / elfutils-debuginfo / elfutils-debugsource / etc");
}
