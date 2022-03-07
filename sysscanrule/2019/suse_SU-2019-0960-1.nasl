#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0960-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(124112);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/17  9:22:56");

  script_cve_id("CVE-2019-6438");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : slurm (SUSE-SU-2019:0960-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for slurm to version 17.11.13 fixes the following issues :

Security issue fixed :

CVE-2019-6438: Fixed a heap overflow on 32-bit systems in xmalloc
(bsc#1123304).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6438/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190960-1/
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
SUSE-SLE-Module-Development-Tools-OBS-15-2019-960=1

SUSE Linux Enterprise Module for HPC 15:zypper in -t patch
SUSE-SLE-Module-HPC-15-2019-960=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm32-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-openlava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-seff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sjstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpmi0-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpmi0-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libslurm32-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libslurm32-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"perl-slurm-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"perl-slurm-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-auth-none-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-auth-none-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-config-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-debugsource-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-devel-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-doc-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-lua-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-lua-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-munge-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-munge-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-node-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-node-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-pam_slurm-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-pam_slurm-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-plugins-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-plugins-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-slurmdbd-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-slurmdbd-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-sql-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-sql-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-torque-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm-torque-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"slurm-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"slurm-debugsource-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"slurm-openlava-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"slurm-seff-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"slurm-sjstat-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"slurm-sview-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"slurm-sview-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"slurm-debuginfo-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"slurm-debugsource-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"slurm-openlava-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"slurm-seff-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"slurm-sjstat-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"slurm-sview-17.11.13-6.15.17")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"slurm-sview-debuginfo-17.11.13-6.15.17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "slurm");
}
