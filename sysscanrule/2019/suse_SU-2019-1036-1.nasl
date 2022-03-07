#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1036-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(124316);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/26  9:36:41");

  script_cve_id("CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : wireshark (SUSE-SU-2019:1036-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark to version 2.4.14 fixes the following 
issues :

Security issues fixed :

CVE-2019-10895: NetScaler file parser crash.

CVE-2019-10899: SRVLOC dissector crash.

CVE-2019-10894: GSS-API dissector crash.

CVE-2019-10896: DOF dissector crash.

CVE-2019-10901: LDSS dissector crash.

CVE-2019-10903: DCERPC SPOOLSS dissector crash.

Non-security issue fixed: Update to version 2.4.14 (bsc#1131945).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10894/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10895/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10896/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10899/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10901/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10903/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191036-1/
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

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-1036=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1036=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");
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
if (os_ver == "SLES15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-debugsource-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-devel-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-ui-qt-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-ui-qt-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwireshark9-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwireshark9-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwiretap7-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwiretap7-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwscodecs1-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwscodecs1-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwsutil8-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwsutil8-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-debugsource-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-debugsource-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-devel-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-ui-qt-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-ui-qt-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwireshark9-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwireshark9-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwiretap7-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwiretap7-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwscodecs1-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwscodecs1-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwsutil8-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwsutil8-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-debuginfo-2.4.14-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-debugsource-2.4.14-3.25.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
