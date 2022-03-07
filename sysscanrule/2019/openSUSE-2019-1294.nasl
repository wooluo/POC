#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1294.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124402);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/30  9:38:18");

  script_cve_id("CVE-2019-3840", "CVE-2019-3886");

  script_name(english:"openSUSE Security Update : libvirt (openSUSE-2019-1294)");
  script_summary(english:"Check for the openSUSE-2019-1294 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libvirt fixes the following issues :

Security issues fixed :

  - CVE-2019-3840: Fixed a NULL pointer dereference
    vulnerability in virJSONValueObjectHasKey function which
    could have resulted in a remote denial of service via
    the guest agent (bsc#1127458). 

  - CVE-2019-3886: Fixed an information leak which allowed
    to retrieve the guest hostname under readonly mode
    (bsc#1131595).

Other issue addressed :

  - cpu: add Skylake-Server and Skylake-Server-IBRS CPU
    models (FATE#327261, bsc#1131955)

  - libxl: save current memory value after successful
    balloon (bsc#1120813).

  - libxl: support Xen's max_grant_frames setting with
    maxGrantFrames attribute on the xenbus controller
    (bsc#1126325).

  - conf: add new 'xenbus' controller type

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/327261"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-admin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-disk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-logical-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-mpath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-scsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-uml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-uml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-vbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-uml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/30");
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

if ( rpm_check(release:"SUSE42.3", reference:"libvirt-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-admin-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-admin-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-client-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-client-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-config-network-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-config-nwfilter-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-interface-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-interface-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-lxc-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-lxc-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-network-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-network-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-nodedev-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-nodedev-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-nwfilter-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-nwfilter-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-qemu-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-qemu-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-secret-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-secret-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-core-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-core-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-disk-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-disk-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-iscsi-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-iscsi-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-logical-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-logical-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-mpath-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-mpath-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-scsi-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-storage-scsi-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-uml-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-uml-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-vbox-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-driver-vbox-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-hooks-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-lxc-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-qemu-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-uml-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-daemon-vbox-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-debugsource-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-devel-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-libs-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-libs-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-lock-sanlock-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-lock-sanlock-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-nss-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvirt-nss-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libvirt-client-debuginfo-32bit-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-debuginfo-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libvirt-daemon-xen-3.3.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libvirt-devel-32bit-3.3.0-24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-admin-debuginfo / libvirt-client / etc");
}
