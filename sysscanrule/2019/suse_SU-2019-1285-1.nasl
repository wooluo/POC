#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1285-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125280);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/20  9:58:35");

  script_cve_id("CVE-2019-3886");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libvirt (SUSE-SU-2019:1285-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libvirt fixes the following issues :

Security issue fixed :

CVE-2019-3886: Fixed an information leak which allowed to retrieve the
guest hostname under readonly mode (bsc#1131595).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3886/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191285-1/
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

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-1285=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1285=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1285=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-admin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-libxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-libxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-disk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-logical-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-mpath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-scsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-plugin-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-plugin-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/20");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-xen-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-admin-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-admin-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-client-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-client-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-config-network-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-config-nwfilter-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-interface-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-interface-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-lxc-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-lxc-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-network-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-network-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-nodedev-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-nodedev-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-nwfilter-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-nwfilter-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-qemu-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-qemu-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-secret-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-secret-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-core-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-core-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-disk-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-disk-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-iscsi-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-iscsi-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-logical-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-logical-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-mpath-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-mpath-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-scsi-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-driver-storage-scsi-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-hooks-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-lxc-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-daemon-qemu-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-debugsource-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-devel-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-doc-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-lock-sanlock-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-lock-sanlock-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-nss-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-nss-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-debugsource-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-plugin-libvirt-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"wireshark-plugin-libvirt-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-debugsource-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-libs-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirt-libs-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libvirt-debugsource-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-plugin-libvirt-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"wireshark-plugin-libvirt-debuginfo-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libvirt-debugsource-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libvirt-libs-4.0.0-9.19.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libvirt-libs-debuginfo-4.0.0-9.19.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
