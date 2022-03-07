#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1508-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125945);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/17 16:04:23");

  script_cve_id("CVE-2019-9928");

  script_name(english:"SUSE SLES12 Security Update : gstreamer-0_10-plugins-base (SUSE-SU-2019:1508-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gstreamer-0_10-plugins-base fixes the following issue:
Security issue fixed :

CVE-2019-9928: Fixed a heap-based overflow in the rtsp connection
parser (bsc#1133375).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9928/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191508-1/
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

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-1508=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-1508=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2019-1508=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-0_10-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-0_10-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-0_10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-0_10-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstinterfaces-0_10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstinterfaces-0_10-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/17");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-0_10-plugins-base-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-0_10-plugins-base-debuginfo-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstapp-0_10-0-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstapp-0_10-0-debuginfo-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstinterfaces-0_10-0-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstinterfaces-0_10-0-debuginfo-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gstreamer-0_10-plugins-base-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gstreamer-0_10-plugins-base-debuginfo-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgstapp-0_10-0-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgstapp-0_10-0-debuginfo-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgstinterfaces-0_10-0-32bit-0.10.36-11.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgstinterfaces-0_10-0-debuginfo-32bit-0.10.36-11.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-0_10-plugins-base");
}
