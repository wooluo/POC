#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2155-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(128021);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2016-5416", "CVE-2018-1054", "CVE-2018-10871", "CVE-2018-1089", "CVE-2018-10935", "CVE-2018-14638", "CVE-2018-14648", "CVE-2019-3883");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : 389-ds (SUSE-SU-2019:2155-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for 389-ds to version 1.4.0.26 fixes the following 
issues :

Security issues fixed :

CVE-2016-5416: Fixed an information disclosure where a anonymous user
could read the default ACI (bsc#991201).

CVE-2018-1054: Fixed a denial of service via search filters in
SetUnicodeStringFromUTF_8() (bsc#1083689).

CVE-2018-1089: Fixed a buffer overflow via large filter value
(bsc#1092187).

CVE-2018-10871: Fixed an information disclosure in certain plugins
leading to the disclosure of plaintext password to an privileged
attackers (bsc#1099465).

CVE-2018-14638: Fixed a denial of service through a crash in
delete_passwdPolicy () (bsc#1108674).

CVE-2018-14648: Fixed a denial of service caused by malformed values
in search queries (bsc#1109609).

CVE-2018-10935: Fixed a denial of service related to ldapsearch with
server side sort (bsc#1105606).

CVE-2019-3883: Fixed a denial of service caused by hanging LDAP
requests over TLS (bsc#1132385).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1099465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=991201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5416/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1054/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10871/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1089/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10935/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14638/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14648/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3883/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192155-1/
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
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2019-2155=1

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-2155=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2155=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2155=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-debugsource-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-devel-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-debugsource-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-snmp-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"389-ds-snmp-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-debugsource-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-devel-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-debugsource-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-snmp-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"389-ds-snmp-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"389-ds-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"389-ds-debugsource-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"389-ds-snmp-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"389-ds-snmp-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"389-ds-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"389-ds-debugsource-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"389-ds-snmp-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"389-ds-snmp-debuginfo-1.4.0.26~git0.8a2d3de6f-4.14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds");
}
