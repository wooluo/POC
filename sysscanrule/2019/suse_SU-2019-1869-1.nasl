#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1869-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126810);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/25  9:40:30");

  script_cve_id("CVE-2019-11709", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11719", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-9811");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2019:1869-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, mozilla-nss fixes the following 
issues :

MozillaFirefox to version ESR 60.8 :

CVE-2019-9811: Sandbox escape via installation of malicious language
pack (bsc#1140868).

CVE-2019-11711: Script injection within domain through inner window
reuse (bsc#1140868).

CVE-2019-11712: Cross-origin POST requests can be made with NPAPI
plugins by following 308 redirects (bsc#1140868).

CVE-2019-11713: Use-after-free with HTTP/2 cached stream
(bsc#1140868).

CVE-2019-11729: Empty or malformed p256-ECDH public keys may trigger a
segmentation fault (bsc#1140868).

CVE-2019-11715: HTML parsing error can contribute to content XSS
(bsc#1140868).

CVE-2019-11717: Caret character improperly escaped in origins
(bsc#1140868).

CVE-2019-11719: Out-of-bounds read when importing curve25519 private
key (bsc#1140868).

CVE-2019-11730: Same-origin policy treats all files in a directory as
having the same-origin (bsc#1140868).

CVE-2019-11709: Multiple Memory safety bugs fixed (bsc#1140868).

mozilla-nss to version 3.44.1: Added IPSEC IKE support to softoken

Many new FIPS test cases

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11709/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11711/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11712/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11713/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11717/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11719/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11729/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11730/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9811/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191869-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2019-1869=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-1869=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1869=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2019-1869=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-1869=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-1869=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1869=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libfreebl3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libfreebl3-hmac-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsoftokn3-hmac-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-debugsource-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-branding-upstream-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-common-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-other-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libfreebl3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libfreebl3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsoftokn3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsoftokn3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-certs-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-certs-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-debugsource-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-devel-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-sysinit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-tools-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mozilla-nss-tools-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libfreebl3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsoftokn3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-branding-upstream-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-devel-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-common-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-other-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfreebl3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfreebl3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfreebl3-hmac-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsoftokn3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsoftokn3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsoftokn3-hmac-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-certs-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-certs-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-debugsource-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-devel-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-sysinit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-tools-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mozilla-nss-tools-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libfreebl3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-branding-upstream-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-common-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-other-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libfreebl3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libfreebl3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsoftokn3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsoftokn3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-certs-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-certs-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-debugsource-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-devel-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-sysinit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-tools-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mozilla-nss-tools-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libfreebl3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsoftokn3-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-branding-upstream-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debuginfo-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debugsource-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-devel-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-common-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-other-60.8.0-3.51.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfreebl3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfreebl3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfreebl3-hmac-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsoftokn3-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsoftokn3-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsoftokn3-hmac-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-certs-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-certs-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-debugsource-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-devel-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-sysinit-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-tools-3.44.1-3.16.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mozilla-nss-tools-debuginfo-3.44.1-3.16.2")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
