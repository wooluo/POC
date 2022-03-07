#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1265-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125244);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/21  9:43:50");

  script_cve_id("CVE-2018-6954", "CVE-2019-3842", "CVE-2019-6454");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : systemd (SUSE-SU-2019:1265-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

Security issues fixed :

CVE-2018-6954: Fixed a vulnerability in the symlink handling of
systemd-tmpfiles which allowed a local user to obtain ownership of
arbitrary files (bsc#1080919).

CVE-2019-3842: Fixed a vulnerability in pam_systemd which allowed a
local user to escalate privileges (bsc#1132348).

CVE-2019-6454: Fixed a denial of service caused by long dbus messages
(bsc#1125352).

Non-security issues fixed: systemd-coredump: generate a stack trace of
all core dumps (jsc#SLE-5933)

udevd: notify when max number value of children is reached only once
per batch of events (bsc#1132400)

sd-bus: bump message queue size again (bsc#1132721)

core: only watch processes when it's really necessary (bsc#955942
bsc#1128657)

rules: load drivers only on 'add' events (bsc#1126056)

sysctl: Don't pass null directive argument to '%s' (bsc#1121563)

Do not automatically online memory on s390x (bsc#1127557)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1130230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6954/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3842/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6454/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191265-1/
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
SUSE-OpenStack-Cloud-7-2019-1265=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-1265=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1265=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-1265=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-1265=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-1265=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-1265=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-1265=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-1265=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-1265=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-1265=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2019-1265=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");
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
if (rpm_check(release:"SLES12", sp:"4", reference:"libsystemd0-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsystemd0-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libudev1-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libudev1-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"systemd-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"systemd-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"systemd-debugsource-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"systemd-sysvinit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"udev-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"udev-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsystemd0-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsystemd0-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libudev1-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libudev1-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"systemd-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"systemd-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debugsource-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-sysvinit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsystemd0-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsystemd0-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsystemd0-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libudev1-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libudev1-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libudev1-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"systemd-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"systemd-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"systemd-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"systemd-debugsource-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"systemd-sysvinit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"udev-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"udev-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev-devel-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debugsource-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-sysvinit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"udev-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"udev-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsystemd0-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsystemd0-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsystemd0-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libudev1-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libudev1-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libudev1-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"systemd-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"systemd-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"systemd-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"systemd-debugsource-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"systemd-sysvinit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"udev-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"udev-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debugsource-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-sysvinit-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-228-150.66.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-debuginfo-228-150.66.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
