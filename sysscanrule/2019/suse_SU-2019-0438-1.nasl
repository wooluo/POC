#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0438-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122342);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/28 10:07:15");

  script_cve_id("CVE-2019-3827");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gvfs (SUSE-SU-2019:0438-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gvfs fixes the following issues :

Security vulnerability fixed :

CVE-2019-3827: Fixed an issue whereby an unprivileged user was not
prompted to give a password when acessing root owned files.
(bsc#1125084)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3827/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190438-1/
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
patch SUSE-SLE-Module-Desktop-Applications-15-2019-438=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-backend-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-backend-afc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-backend-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-backend-samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-backends");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-backends-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvfs-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/20");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-backend-afc-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-backend-afc-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-backend-samba-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-backend-samba-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-backends-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-backends-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-debugsource-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-devel-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-fuse-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gvfs-fuse-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-backend-afc-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-backend-afc-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-backend-samba-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-backend-samba-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-backends-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-backends-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-debuginfo-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-debugsource-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-devel-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-fuse-1.34.2.1-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gvfs-fuse-debuginfo-1.34.2.1-4.6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs");
}
