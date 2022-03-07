#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0426-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122312);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/04 11:19:02");

  script_cve_id("CVE-2019-6454");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : systemd (SUSE-SU-2019:0426-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

CVE-2019-6454: Overlong DBUS messages could be used to crash systemd
(bsc#1125352)

units: make sure initrd-cleanup.service terminates before switching to
rootfs (bsc#1123333)

logind: fix bad error propagation

login: log session state 'closing' (as well as New/Removed)

logind: fix borked r check

login: don't remove all devices from PID1 when only one was removed

login: we only allow opening character devices

login: correct comment in session_device_free()

login: remember that fds received from PID1 need to be removed
eventually

login: fix FDNAME in call to sd_pid_notify_with_fds()

logind: fd 0 is a valid fd

logind: rework sd_eviocrevoke()

logind: check file is device node before using .st_rdev

logind: use the new FDSTOREREMOVE=1 sd_notify() message (bsc#1124153)

core: add a new sd_notify() message for removing fds from the FD store
again

logind: make sure we don't trip up on half-initialized session devices
(bsc#1123727)

fd-util: accept that kcmp might fail with EPERM/EACCES

core: Fix use after free case in load_from_path() (bsc#1121563)

core: include Found state in device dumps

device: fix serialization and deserialization of DeviceFound

fix path in btrfs rule (#6844)

assemble multidevice btrfs volumes without external tools (#6607)
(bsc#1117025)

Update systemd-system.conf.xml (bsc#1122000)

units: inform user that the default target is started after exiting
from rescue or emergency mode

core: free lines after reading them (bsc#1123892)

sd-bus: if we receive an invalid dbus message, ignore and proceeed

automount: don't pass non-blocking pipe to kernel.

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6454/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190426-1/
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
SUSE-SLE-Module-Development-Tools-OBS-15-2019-426=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-426=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-mymachines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-container-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-coredump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-container-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-container-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-coredump-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-coredump-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini1-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini1-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-myhostname-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-myhostname-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-mymachines-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-mymachines-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-systemd-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-systemd-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debugsource-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-logger-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-container-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-container-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-coredump-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-coredump-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-debugsource-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-sysvinit-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev1-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev1-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-container-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-container-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-coredump-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-coredump-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debugsource-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-sysvinit-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-234-24.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini1-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini1-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-myhostname-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-myhostname-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-mymachines-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-mymachines-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-systemd-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-systemd-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debugsource-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-logger-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-container-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-container-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-coredump-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-coredump-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-debugsource-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-sysvinit-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-mini-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-mini-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev1-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev1-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-container-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-container-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-coredump-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-coredump-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debuginfo-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debugsource-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-devel-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-sysvinit-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-234-24.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-debuginfo-234-24.25.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
