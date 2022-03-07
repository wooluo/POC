#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1722-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126461);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/03 12:01:37");

  script_cve_id("CVE-2018-16428", "CVE-2018-16429", "CVE-2019-12450");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : glib2 (SUSE-SU-2019:1722-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glib2 provides the following fix :

Security issues fixed :

CVE-2019-12450: Fixed an improper file permission when copy operation
takes place (bsc#1137001).

CVE-2018-16428: Avoid a NULL pointer dereference that could crash
glib2 users in markup processing (bnc#1107121).

CVE-2018-16429: Fixed out-of-bounds read vulnerability
ing_markup_parse_context_parse() (bsc#1107116).

Non-security issues fixed: Install dummy *-mimeapps.list files to
prevent dead symlinks. (bsc#1061599)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1137001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16428/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16429/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12450/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191722-1/
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

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-1722=1

SUSE Linux Enterprise Workstation Extension 12-SP5:zypper in -t patch
SUSE-SLE-WE-12-SP5-2019-1722=1

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2019-1722=1

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2019-1722=1

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2019-1722=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-1722=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1722=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-1722=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2019-1722=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-1722=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-1722=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-1722=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-1722=1

SUSE Linux Enterprise Desktop 12-SP5:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP5-2019-1722=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-1722=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-1722=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-1722=1

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2019-1722=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glib2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glib2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-fam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libglib-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libglib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libglib-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmodule-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmodule-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgobject-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgobject-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgthread-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgthread-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/03");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgio-fam-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgio-fam-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgio-fam-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgio-fam-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"glib2-debugsource-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"glib2-tools-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"glib2-tools-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgio-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgio-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgio-fam-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgio-fam-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libglib-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libglib-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgmodule-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgmodule-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgobject-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgobject-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgthread-2_0-0-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-2.48.2-12.12.2")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libgthread-2_0-0-debuginfo-32bit-2.48.2-12.12.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2");
}