#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-161.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122145);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/13  9:26:32");

  script_cve_id("CVE-2018-11212", "CVE-2019-2422", "CVE-2019-2426");

  script_name(english:"openSUSE Security Update : java-11-openjdk (openSUSE-2019-161)");
  script_summary(english:"Check for the openSUSE-2019-161 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-11-openjdk to version 11.0.2+7 fixes the
following issues :

Security issues fixed :

  - CVE-2019-2422: Better FileChannel transfer performance
    (bsc#1122293)

  - CVE-2019-2426: Improve web server connections

  - CVE-2018-11212: Improve JPEG processing (bsc#1122299)

  - Better route routing

  - Better interface enumeration

  - Better interface lists

  - Improve BigDecimal support

  - Improve robot support

  - Better icon support

  - Choose printer defaults

  - Proper allocation handling

  - Initial class initialization

  - More reliable p11 transactions

  - Improve NIO stability

  - Better loading of classloader classes

  - Strengthen Windows Access Bridge Support

  - Improved data set handling

  - Improved LSA authentication

  - Libsunmscapi improved interactions

Non-security issues fix :

  - Do not resolve by default the added JavaEE modules
    (bsc#1120431)

  - ~2.5% regression on compression benchmark starting with
    12-b11

  - java.net.http.HttpClient hangs on 204 reply without
    Content-length 0

  - Add additional TeliaSonera root certificate

  - Add more ld preloading related info to hs_error file on
    Linux

  - Add test to exercise server-side client hello processing

  - AES encrypt performance regression in jdk11b11

  - AIX: ProcessBuilder: Piping between created processes
    does not work.

  - AIX: Some class library files are missing the Classpath
    exception

  - AppCDS crashes for some uses with JRuby

  - Automate vtable/itable stub size calculation

  - BarrierSetC1::generate_referent_check() confuses
    register allocator

  - Better HTTP Redirection

  - Catastrophic size_t underflow in BitMap::*_large methods

  - Clip.isRunning() may return true after Clip.stop() was
    called

  - Compiler thread creation should be bounded by available
    space in memory and Code Cache

  - com.sun.net.httpserver.HttpServer returns Content-length
    header for 204 response code

  - Default mask register for avx512 instructions

  - Delayed starting of debugging via jcmd

  - Disable all DES cipher suites

  - Disable anon and NULL cipher suites

  - Disable unsupported GCs for Zero

  - Epsilon alignment adjustments can overflow max TLAB size

  - Epsilon elastic TLAB sizing may cause misalignment

  - HotSpot update for vm_version.cpp to recognise updated
    VS2017

  - HttpClient does not retrieve files with large sizes over
    HTTP/1.1

  - IIOException 'tEXt chunk length is not proper' on
    opening png file

  - Improve TLS connection stability again

  - InitialDirContext ctor sometimes throws NPE if the
    server has sent a disconnection

  - Inspect stack during error reporting

  - Instead of circle rendered in appl window, but ellipse
    is produced JEditor Pane

  - Introduce diagnostic flag to abort VM on failed JIT
    compilation

  - Invalid assert(HeapBaseMinAddress > 0) in
    ReservedHeapSpace::initialize_compressed_heap

  - jar has issues with UNC-path arguments for the jar -C
    parameter [windows]

  - java.net.http HTTP client should allow specifying Origin
    and Referer headers

  - java.nio.file.Files.writeString writes garbled UTF-16
    instead of UTF-8

  - JDK 11.0.1 l10n resource file update

  - JDWP Transport Listener: dt_socket thread crash

  - JVMTI ResourceExhausted should not be posted in
    CompilerThread

  - LDAPS communication failure with jdk 1.8.0_181

  - linux: Poor StrictMath performance due to non-optimized
    compilation

  - Missing synchronization when reading counters for live
    threads and peak thread count

  - NPE in SupportedGroupsExtension

  - OpenDataException thrown when constructing CompositeData
    for StackTraceElement

  - Parent class loader may not have a referred
    ClassLoaderData instance when obtained in
    Klass::class_in_module_of_loader

  - Populate handlers while holding streamHandlerLock

  - ppc64: Enable POWER9 CPU detection

  - print_location is not reliable enough (printing register
    info)

  - Reconsider default option for ClassPathURLCheck change
    done in JDK-8195874

  - Register to register spill may use AVX 512 move
    instruction on unsupported platform.

  - s390: Use of shift operators not covered by cpp standard

  - serviceability/sa/TestUniverse.java#id0 intermittently
    fails with assert(get_instanceKlass()->is_loaded())
    failed: must be at least loaded

  - SIGBUS in CodeHeapState::print_names()

  - SIGSEGV in MethodArityHistogram() with
    -XX:+CountCompiledCalls

  - Soft reference reclamation race in
    com.sun.xml.internal.stream.util.ThreadLocalBufferAlloca
    tor

  - Swing apps are slow if displaying from a remote source
    to many local displays

  - switch jtreg to 4.2b13

  - Test library OSInfo.getSolarisVersion cannot determine
    Solaris version

  - TestOptionsWithRanges.java is very slow

  - TestOptionsWithRanges.java of '-XX:TLABSize=2147483648'
    fails intermittently

  - The Japanese message of FileNotFoundException garbled

  - The 'supported_groups' extension in ServerHellos

  - ThreadInfoCompositeData.toCompositeData fails to map
    ThreadInfo to CompositeData

  - TimeZone.getDisplayName given Locale.US doesn't always
    honor the Locale.

  - TLS 1.2 Support algorithm in SunPKCS11 provider

  - TLS 1.3 handshake server name indication is missing on a
    session resume

  - TLS 1.3 server fails if ClientHello doesn't have
    pre_shared_key and psk_key_exchange_modes

  - TLS 1.3 interop problems with OpenSSL 1.1.1 when used on
    the client side with mutual auth

  - tz: Upgrade time-zone data to tzdata2018g

  - Undefined behaviour in ADLC

  - Update avx512 implementation

  - URLStreamHandler initialization race

  - UseCompressedOops requirement check fails fails on
    32-bit system

  - windows: Update OS detection code to recognize Windows
    Server 2019

  - x86: assert on unbound assembler Labels used as branch
    targets

  - x86: jck tests for ldc2_w bytecode fail

  - x86: sharedRuntimeTrig/sharedRuntimeTrans compiled
    without optimization

  - '-XX:OnOutOfMemoryError' uses fork instead of vfork

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122299"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-11-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/13");
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

if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-accessibility-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-accessibility-debuginfo-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-debuginfo-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-debugsource-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-demo-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-devel-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-headless-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-javadoc-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-jmods-11.0.2.0-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-src-11.0.2.0-lp150.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-accessibility / etc");
}
