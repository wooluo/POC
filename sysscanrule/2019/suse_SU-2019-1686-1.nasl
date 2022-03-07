#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1686-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126237);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-10161", "CVE-2019-10167");

  script_name(english:"SUSE SLES12 Security Update : libvirt (SUSE-SU-2019:1686-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libvirt fixes the following issues :

Security issues fixed :

CVE-2019-10161: Fixed virDomainSaveImageGetXMLDesc API which could
accept a path parameter pointing anywhere on the system and
potentially leading to execution of a malicious file with root
privileges by libvirtd (bsc#1138301).

CVE-2019-10167: Fixed an issue with virConnectGetDomainCapabilities
API which could have been used to execute arbitrary emulators
(bsc#1138303).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10161/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10167/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191686-1/
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
SUSE-SLE-SAP-12-SP1-2019-1686=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-1686=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-xen-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-client-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-client-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-config-network-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-config-nwfilter-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-interface-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-interface-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-lxc-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-lxc-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-network-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-network-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nodedev-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nodedev-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nwfilter-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nwfilter-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-qemu-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-qemu-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-secret-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-secret-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-storage-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-storage-debuginfo-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-lxc-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-qemu-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-debugsource-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-doc-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-lock-sanlock-1.2.18.4-22.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-lock-sanlock-debuginfo-1.2.18.4-22.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
