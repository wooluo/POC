#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0418-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122307);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/19  9:39:24");

  script_cve_id("CVE-2019-6446");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : python-numpy (SUSE-SU-2019:0418-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-numpy fixes the following issue :

Security issue fixed :

CVE-2019-6446: Set allow_pickle to false by default to restrict
loading untrusted content (bsc#1122208). With this update we decrease
the possibility of allowing remote attackers to execute arbitrary code
by misusing numpy.load(). A warning during runtime will show-up when
the allow_pickle is not explicitly set.

NOTE: By applying this update the behavior of python-numpy changes,
which might break your application. In order to get the old behaviour
back, you have to explicitly set `allow_pickle` to True. Be aware that
this should only be done for trusted input, as loading untrusted input
might lead to arbitrary code execution.

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6446/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190418-1/
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

SUSE Linux Enterprise Module for HPC 15:zypper in -t patch
SUSE-SLE-Module-HPC-15-2019-418=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-418=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-numpy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-numpy_1_14_0-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-numpy_1_14_0-gnu-hpc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy_1_14_0-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy_1_14_0-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-numpy_1_14_0-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy_1_14_0-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy_1_14_0-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-numpy_1_14_0-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python-numpy_1_14_0-gnu-hpc-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python-numpy_1_14_0-gnu-hpc-debugsource-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python2-numpy-gnu-hpc-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python2-numpy-gnu-hpc-devel-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python2-numpy_1_14_0-gnu-hpc-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python2-numpy_1_14_0-gnu-hpc-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python2-numpy_1_14_0-gnu-hpc-devel-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python3-numpy-gnu-hpc-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python3-numpy-gnu-hpc-devel-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python3-numpy_1_14_0-gnu-hpc-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python3-numpy_1_14_0-gnu-hpc-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python3-numpy_1_14_0-gnu-hpc-devel-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-numpy-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-numpy-debugsource-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python2-numpy-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python2-numpy-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python2-numpy-devel-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-numpy-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-numpy-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-numpy-devel-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-numpy-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-numpy-debugsource-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python2-numpy-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python2-numpy-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python2-numpy-devel-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-numpy-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-numpy-debuginfo-1.14.0-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-numpy-devel-1.14.0-4.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-numpy");
}
