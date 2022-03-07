#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1952.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128015);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-11922");

  script_name(english:"openSUSE Security Update : zstd (openSUSE-2019-1952)");
  script_summary(english:"Check for the openSUSE-2019-1952 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zstd fixes the following issues :

  - Update to version 1.4.2 :

  - bug: Fix bug in zstd-0.5 decoder by @terrelln (#1696)

  - bug: Fix seekable decompression in-memory API by
    @iburinoc (#1695)

  - bug: Close minor memory leak in CLI by @LeeYoung624
    (#1701)

  - misc: Validate blocks are smaller than size limit by
    @vivekmig (#1685)

  - misc: Restructure source files by @ephiepark (#1679)

  - Update to version 1.4.1 :

  - bug: Fix data corruption in niche use cases by @terrelln
    (#1659)

  - bug: Fuzz legacy modes, fix uncovered bugs by @terrelln
    (#1593, #1594, #1595)

  - bug: Fix out of bounds read by @terrelln (#1590)

  - perf: Improve decode speed by ~7% @mgrice (#1668)

  - perf: Slightly improved compression ratio of level 3 and
    4 (ZSTD_dfast) by @cyan4973 (#1681)

  - perf: Slightly faster compression speed when re-using a
    context by @cyan4973 (#1658)

  - perf: Improve compression ratio for small windowLog by
    @cyan4973 (#1624)

  - perf: Faster compression speed in high compression mode
    for repetitive data by @terrelln (#1635)

  - api: Add parameter to generate smaller dictionaries by
    @tyler-tran (#1656)

  - cli: Recognize symlinks when built in C99 mode by
    @felixhandte (#1640)

  - cli: Expose cpu load indicator for each file on -vv mode
    by @ephiepark (#1631)

  - cli: Restrict read permissions on destination files by
    @chungy (#1644)

  - cli: zstdgrep: handle -f flag by @felixhandte (#1618)

  - cli: zstdcat: follow symlinks by @vejnar (#1604)

  - doc: Remove extra size limit on compressed blocks by
    @felixhandte (#1689)

  - doc: Fix typo by @yk-tanigawa (#1633)

  - doc: Improve documentation on streaming buffer sizes by
    @cyan4973 (#1629)

  - build: CMake: support building with LZ4 @leeyoung624
    (#1626)

  - build: CMake: install zstdless and zstdgrep by
    @leeyoung624 (#1647)

  - build: CMake: respect existing uninstall target by
    @j301scott (#1619)

  - build: Make: skip multithread tests when built without
    support by @michaelforney (#1620)

  - build: Make: Fix examples/ test target by @sjnam (#1603)

  - build: Meson: rename options out of deprecated namespace
    by @lzutao (#1665)

  - build: Meson: fix build by @lzutao (#1602)

  - build: Visual Studio: don't export symbols in static lib
    by @scharan (#1650)

  - build: Visual Studio: fix linking by @absotively (#1639)

  - build: Fix MinGW-W64 build by @myzhang1029 (#1600)

  - misc: Expand decodecorpus coverage by @ephiepark (#1664)

  - Add baselibs.conf: libarchive gained zstd support and
    provides

    -32bit libraries. This means, zstd also needs to provide
    -32bit libs.

  - Update to new upstream release 1.4.0

  - perf: level 1 compression speed was improved

  - cli: added --[no-]compress-literals flag to enable or
    disable literal compression

  - Reword 'real-time' in description by some actual
    statistics, because 603MB/s (lowest zstd level) is not
    'real-time' for quite some applications.

  - zstd 1.3.8 :

  - better decompression speed on large files (+7%) and cold
    dictionaries (+15%)

  - slightly better compression ratio at high compression
    modes

  - new --rsyncable mode

  - support decompression of empty frames into NULL (used to
    be an error)

  - support ZSTD_CLEVEL environment variable

  - --no-progress flag, preserving final summary

  - various CLI fixes

  - fix race condition in one-pass compression functions
    that could allow out of bounds write (CVE-2019-11922,
    boo#1142941)

  - zstd 1.3.7 :

  - fix ratio for dictionary compression at levels 9 and 10

  - add man pages for zstdless and zstdgrep

  - includes changes from zstd 1.3.6 :

  - faster dictionary builder, also the new default for
    --train

  - previous (slower, slightly higher quality) dictionary
    builder to be selected via --train-cover

  - Faster dictionary decompression and compression under
    memory limits with many dictionaries used simultaneously

  - New command --adapt for compressed network piping of
    data adjusted to the perceived network conditions

  - update to 1.3.5 :

  - much faster dictionary compression

  - small quality improvement for dictionary generation

  - slightly improved performance at high compression levels

  - automatic memory release for long duration contexts

  - fix overlapLog can be manually set

  - fix decoding invalid lz4 frames

  - fix performance degradation for dictionary compression
    when using advanced API

  - fix pzstd tests

  - enable pzstd (parallel zstd)

  - Use %license instead of %doc [boo#1082318]

  - Add disk _constraints to fix ppc64le build

  - Use FAT LTO objects in order to provide proper static
    library (boo#1133297)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142941"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zstd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzstd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zstd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zstd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zstd-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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

if ( rpm_check(release:"SUSE15.0", reference:"libzstd-devel-1.4.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libzstd-devel-static-1.4.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libzstd1-1.4.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libzstd1-debuginfo-1.4.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zstd-1.4.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zstd-debuginfo-1.4.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zstd-debugsource-1.4.2-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzstd-devel / libzstd-devel-static / libzstd1 / etc");
}
