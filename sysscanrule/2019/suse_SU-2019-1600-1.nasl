#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1600-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126155);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/24 10:35:06");

  script_cve_id("CVE-2019-9928");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : gstreamer-plugins-base (SUSE-SU-2019:1600-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gstreamer-plugins-base fixes the following issue:
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
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191600-1/
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
SUSE-OpenStack-Cloud-7-2019-1600=1

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2019-1600=1

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2019-1600=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-1600=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1600=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-1600=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-1600=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-1600=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-1600=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-1600=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-1600=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-1600=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-1600=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstAudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstPbutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstTag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstVideo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/24");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"gstreamer-plugins-base-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"gstreamer-plugins-base-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"gstreamer-plugins-base-debugsource-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstallocators-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstallocators-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstapp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstapp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstaudio-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstaudio-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstfft-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstfft-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstpbutils-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstpbutils-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstriff-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstriff-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstrtp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstrtp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstrtsp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstrtsp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstsdp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstsdp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgsttag-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgsttag-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstvideo-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstvideo-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"gstreamer-plugins-base-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstapp-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstapp-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstaudio-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstpbutils-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgsttag-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgsttag-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstvideo-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gstreamer-plugins-base-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gstreamer-plugins-base-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gstreamer-plugins-base-debugsource-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstallocators-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstallocators-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstapp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstapp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstaudio-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstaudio-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstfft-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstfft-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstpbutils-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstpbutils-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstriff-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstriff-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstrtp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstrtp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstrtsp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstrtsp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstsdp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstsdp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgsttag-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgsttag-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstvideo-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstvideo-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gstreamer-plugins-base-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstapp-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstapp-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstaudio-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstpbutils-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgsttag-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgsttag-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstvideo-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"gstreamer-plugins-base-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"gstreamer-plugins-base-debugsource-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstallocators-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstallocators-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstapp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstaudio-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstfft-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstriff-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstriff-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstrtp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstrtp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstrtsp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstrtsp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstsdp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstsdp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgsttag-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstvideo-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gstreamer-plugins-base-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gstreamer-plugins-base-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gstreamer-plugins-base-debugsource-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstallocators-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstallocators-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstapp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstapp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstaudio-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstaudio-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstfft-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstfft-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstpbutils-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstpbutils-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstriff-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstriff-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstrtp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstrtp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstrtsp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstrtsp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstsdp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstsdp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgsttag-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgsttag-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstvideo-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstvideo-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gstreamer-plugins-base-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstapp-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstapp-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstaudio-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstpbutils-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgsttag-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgsttag-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstvideo-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"gstreamer-plugins-base-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"gstreamer-plugins-base-debugsource-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstallocators-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstallocators-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstapp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstaudio-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstfft-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstpbutils-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstriff-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstriff-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstrtp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstrtp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstrtsp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstrtsp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstsdp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstsdp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgsttag-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstvideo-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-GstAudio-1_0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-GstPbutils-1_0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-GstTag-1_0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-GstVideo-1_0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gstreamer-plugins-base-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gstreamer-plugins-base-debugsource-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstallocators-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstallocators-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstapp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstaudio-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstfft-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstpbutils-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstriff-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstriff-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstrtp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstrtp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstrtsp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstrtsp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstsdp-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstsdp-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgsttag-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstvideo-1_0-0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-GstAudio-1_0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-GstPbutils-1_0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-GstTag-1_0-1.8.3-13.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-GstVideo-1_0-1.8.3-13.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-base");
}
