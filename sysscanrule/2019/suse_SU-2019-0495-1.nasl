#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0495-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122472);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : containerd, docker, docker-runc, golang-github-docker-libnetwork, runc (SUSE-SU-2019:0495-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork, runc fixes the following issues :

Security issues fixed :

CVE-2018-16875: Fixed a CPU Denial of Service (bsc#1118899).

CVE-2018-16874: Fixed a vulnerabity in go get command which could
allow directory traversal in GOPATH mode (bsc#1118898).

CVE-2018-16873: Fixed a vulnerability in go get command which could
allow remote code execution when executed with -u in GOPATH mode
(bsc#1118897).

CVE-2019-5736: Effectively copying /proc/self/exe during re-exec to
avoid write attacks to the host runc binary, which could lead to a
container breakout (bsc#1121967).

Other changes and fixes: Update shell completion to use Group:
System/Shells.

Add daemon.json file with rotation logs configuration (bsc#1114832)

Update to Docker 18.09.1-ce (bsc#1124308) and to to runc 96ec2177ae84.
See upstream changelog in the packaged
/usr/share/doc/packages/docker/CHANGELOG.md.

Update go requirements to >= go1.10

Use -buildmode=pie for tests and binary build (bsc#1048046 and
bsc#1051429).

Remove the usage of 'cp -r' to reduce noise in the build logs.

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16873/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16874/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16875/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-5736/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190495-1/
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

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-495=1

SUSE Linux Enterprise Module for Containers 15:zypper in -t patch
SUSE-SLE-Module-Containers-15-2019-495=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/27");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-ctr-1.2.2-5.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debuginfo-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debugsource-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-debuginfo-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2711_2cfbf9b1f981-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-1.2.2-5.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debuginfo-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debugsource-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-0.7.0.1+gitr2711_2cfbf9b1f981-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2711_2cfbf9b1f981-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-1.0.0rc6+gitr3748_96ec2177ae84-6.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-debuginfo-1.0.0rc6+gitr3748_96ec2177ae84-6.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"containerd-ctr-1.2.2-5.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-debuginfo-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-debugsource-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-debuginfo-18.09.1_ce-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2711_2cfbf9b1f981-4.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / docker / docker-runc / golang-github-docker-libnetwork / runc");
}
