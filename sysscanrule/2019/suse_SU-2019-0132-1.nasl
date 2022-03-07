#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0132-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(121300);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6110", "CVE-2019-6111");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssh (SUSE-SU-2019:0132-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssh fixes the following issues :

Security issue fixed :

CVE-2018-20685: Fixed an issue where scp client allows remote SSH
servers to bypass intended access restrictions (bsc#1121571)

CVE-2019-6109: Fixed an issue where the scp client would allow
malicious remote SSH servers to manipulate terminal output via the
object name, e.g. by inserting ANSI escape sequences (bsc#1121816)

CVE-2019-6110: Fixed an issue where the scp client would allow
malicious remote SSH servers to manipulate stderr output, e.g. by
inserting ANSI escape sequences (bsc#1121818)

CVE-2019-6111: Fixed an issue where the scp client would allow
malicious remote SSH servers to execute directory traversal attacks
and overwrite files (bsc#1121821)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20685/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6109/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6110/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6111/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190132-1/
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
SUSE-OpenStack-Cloud-7-2019-132=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-132=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-132=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-132=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-132=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-132=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-132=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-132=1

SUSE Enterprise Storage 4:zypper in -t patch SUSE-Storage-4-2019-132=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2019-132=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/22");
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
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-askpass-gnome-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-askpass-gnome-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-debugsource-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-fips-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-helpers-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"openssh-helpers-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-askpass-gnome-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-askpass-gnome-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-debugsource-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-fips-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-helpers-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssh-helpers-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-askpass-gnome-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-askpass-gnome-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-debugsource-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-fips-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-helpers-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openssh-helpers-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-askpass-gnome-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-askpass-gnome-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-debugsource-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-fips-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-helpers-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssh-helpers-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"openssh-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"openssh-askpass-gnome-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"openssh-askpass-gnome-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"openssh-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"openssh-debugsource-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"openssh-helpers-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"openssh-helpers-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssh-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssh-askpass-gnome-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssh-askpass-gnome-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssh-debuginfo-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssh-debugsource-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssh-helpers-7.2p2-74.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssh-helpers-debuginfo-7.2p2-74.35.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
