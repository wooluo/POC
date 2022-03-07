#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-268.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122529);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/04 11:19:02");

  script_cve_id("CVE-2019-6454");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2019-268)");
  script_summary(english:"Check for the openSUSE-2019-268 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

Security vulnerability fixed :

  - CVE-2019-6454: Fixed a crash of PID1 by sending
    specially crafted D-BUS message on the system bus by an
    unprivileged user (bsc#1125352)

Other bug fixes and changes :

  - journal-remote: set a limit on the number of fields in a
    message

  - journal-remote: verify entry length from header

  - journald: set a limit on the number of fields (1k)

  - journald: do not store the iovec entry for process
    commandline on stack

  - core: include Found state in device dumps

  - device: fix serialization and deserialization of
    DeviceFound

  - fix path in btrfs rule (#6844)

  - assemble multidevice btrfs volumes without external
    tools (#6607) (bsc#1117025)

  - Update systemd-system.conf.xml (bsc#1122000)

  - units: inform user that the default target is started
    after exiting from rescue or emergency mode

  - manager: don't skip sigchld handler for main and control
    pid for services (#3738)

  - core: Add helper functions unit_{main, control}_pid

  - manager: Fixing a debug printf formatting mistake
    (#3640)

  - manager: Only invoke a single sigchld per unit within a
    cleanup cycle (bsc#1117382)

  - core: update invoke_sigchld_event() to handle NULL
    ->sigchld_event()

  - sd-event: expose the event loop iteration counter via
    sd_event_get_iteration() (#3631)

  - unit: rework a bit how we keep the service fdstore from
    being destroyed during service restart (bsc#1122344)

  - core: when restarting services, don't close fds

  - cryptsetup: Add dependency on loopback setup to
    generated units

  - journal-gateway: use localStorage['cursor'] only when it
    has valid value

  - journal-gateway: explicitly declare local variables

  - analyze: actually select longest activated-time of
    services

  - sd-bus: fix implicit downcast of bitfield reported by
    LGTM

  - core: free lines after reading them (bsc#1123892)

  - pam_systemd: reword message about not creating a session
    (bsc#1111498)

  - pam_systemd: suppress LOG_DEBUG log messages if
    debugging is off (bsc#1111498)

  - main: improve RLIMIT_NOFILE handling (#5795)
    (bsc#1120658)

  - sd-bus: if we receive an invalid dbus message, ignore
    and proceeed

  - automount: don't pass non-blocking pipe to kernel.

  - units: make sure initrd-cleanup.service terminates
    before switching to rootfs (bsc#1123333)

  - units: add Wants=initrd-cleanup.service to
    initrd-switch-root.target (#4345) (bsc#1123333)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123892"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-devel-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini-devel-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-bash-completion-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debugsource-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-devel-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-logger-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-bash-completion-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debugsource-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-devel-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-sysvinit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-sysvinit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-debuginfo-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-32bit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-32bit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-32bit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-32bit-228-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-68.1") ) flag++;

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
