#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0655-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122997);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/27 11:14:35");

  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libssh2_org (SUSE-SU-2019:0655-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libssh2_org fixes the following issues :

Security issues fixed :

CVE-2019-3861: Fixed Out-of-bounds reads with specially crafted SSH
packets (bsc#1128490).

CVE-2019-3862: Fixed Out-of-bounds memory comparison with specially
crafted message channel request packet (bsc#1128492).

CVE-2019-3860: Fixed Out-of-bounds reads with specially crafted SFTP
packets (bsc#1128481).

CVE-2019-3863: Fixed an Integer overflow in user authenticate keyboard
interactive which could allow out-of-bounds writes with specially
crafted keyboard responses (bsc#1128493).

CVE-2019-3856: Fixed a potential Integer overflow in keyboard
interactive handling which could allow out-of-bounds write with
specially crafted payload (bsc#1128472).

CVE-2019-3859: Fixed Out-of-bounds reads with specially crafted
payloads due to unchecked use of _libssh2_packet_require and
_libssh2_packet_requirev (bsc#1128480).

CVE-2019-3855: Fixed a potential Integer overflow in transport read
which could allow out-of-bounds write with specially crafted payload
(bsc#1128471).

CVE-2019-3858: Fixed a potential zero-byte allocation which could lead
to an out-of-bounds read with a specially crafted SFTP packet
(bsc#1128476).

CVE-2019-3857: Fixed a potential Integer overflow which could lead to
zero-byte allocation and out-of-bounds with specially crafted message
channel request SSH packet (bsc#1128474).

Other issue addressed: Libbssh2 will stop using keys unsupported types
in the known_hosts file (bsc#1091236).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3855/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3856/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3857/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3858/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3859/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3860/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3861/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3862/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3863/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190655-1/
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
SUSE-OpenStack-Cloud-7-2019-655=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-655=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-655=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-655=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-655=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-655=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-655=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-655=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-655=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-655=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2019-655=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-655=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-655=1

SUSE Enterprise Storage 4:zypper in -t patch SUSE-Storage-4-2019-655=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2019-655=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2_org-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/21");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1|2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libssh2-1-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libssh2-1-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libssh2-1-debuginfo-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libssh2-1-debuginfo-32bit-1.4.3-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libssh2_org-debugsource-1.4.3-20.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2_org");
}
