#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-255.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122496);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/04 11:19:02");

  script_cve_id("CVE-2019-6454");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2019-255)");
  script_summary(english:"Check for the openSUSE-2019-255 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

  - CVE-2019-6454: Overlong DBUS messages could be used to
    crash systemd (bsc#1125352)

  - units: make sure initrd-cleanup.service terminates
    before switching to rootfs (bsc#1123333)

  - logind: fix bad error propagation

  - login: log session state 'closing' (as well as
    New/Removed)

  - logind: fix borked r check

  - login: don't remove all devices from PID1 when only one
    was removed

  - login: we only allow opening character devices

  - login: correct comment in session_device_free()

  - login: remember that fds received from PID1 need to be
    removed eventually

  - login: fix FDNAME in call to sd_pid_notify_with_fds()

  - logind: fd 0 is a valid fd

  - logind: rework sd_eviocrevoke()

  - logind: check file is device node before using .st_rdev

  - logind: use the new FDSTOREREMOVE=1 sd_notify() message
    (bsc#1124153)

  - core: add a new sd_notify() message for removing fds
    from the FD store again

  - logind: make sure we don't trip up on half-initialized
    session devices (bsc#1123727)

  - fd-util: accept that kcmp might fail with EPERM/EACCES

  - core: Fix use after free case in load_from_path()
    (bsc#1121563)

  - core: include Found state in device dumps

  - device: fix serialization and deserialization of
    DeviceFound

  - fix path in btrfs rule (#6844)

  - assemble multidevice btrfs volumes without external
    tools (#6607) (bsc#1117025)

  - Update systemd-system.conf.xml (bsc#1122000)

  - units: inform user that the default target is started
    after exiting from rescue or emergency mode

  - core: free lines after reading them (bsc#1123892)

  - sd-bus: if we receive an invalid dbus message, ignore
    and proceeed

  - automount: don't pass non-blocking pipe to kernel. This
    update was imported from the SUSE:SLE-15:Update update
    project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125352"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-container-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-coredump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-container-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-container-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-coredump-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-coredump-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libsystemd0-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsystemd0-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsystemd0-mini-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsystemd0-mini-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudev-devel-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudev-mini-devel-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudev-mini1-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudev-mini1-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudev1-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudev1-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nss-myhostname-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nss-myhostname-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nss-mymachines-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nss-mymachines-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nss-systemd-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nss-systemd-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-bash-completion-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-container-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-container-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-coredump-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-coredump-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-debugsource-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-devel-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-logger-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-bash-completion-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-container-mini-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-container-mini-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-coredump-mini-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-coredump-mini-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-debugsource-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-devel-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-mini-sysvinit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"systemd-sysvinit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udev-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udev-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udev-mini-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udev-mini-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsystemd0-32bit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libudev-devel-32bit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libudev1-32bit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"nss-myhostname-32bit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"nss-myhostname-32bit-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"nss-mymachines-32bit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"nss-mymachines-32bit-debuginfo-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"systemd-32bit-234-lp150.20.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-lp150.20.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsystemd0-mini / libsystemd0-mini-debuginfo / libudev-mini-devel / etc");
}
