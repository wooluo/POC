#
# (C) WebRAY Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0024.
#

include("compat.inc");

if (description)
{
  script_id(125754);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/07  9:45:01");

  script_cve_id("CVE-2011-1079", "CVE-2018-14633", "CVE-2018-20836", "CVE-2019-11810", "CVE-2019-11815", "CVE-2019-11884", "CVE-2019-3459", "CVE-2019-3819");
  script_bugtraq_id(46616);

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0024)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - hugetlbfs: don't retry when pool page allocations start
    to fail (Mike Kravetz) [Orabug: 29324267]

  - x86/speculation: RSB stuffing with retpoline on Skylake+
    cpus (William Roche) [Orabug: 29660924]

  - x86/speculation: reformatting RSB overwrite macro
    (William Roche) [Orabug: 29660924]

  - x86/speculation: Dynamic enable and disable of RSB
    stuffing with IBRS&!SMEP (William Roche) [Orabug:
    29660924]

  - x86/speculation: STUFF_RSB dynamic enable (William
    Roche) [Orabug: 29660924]

  - int3 handler better address space detection on
    interrupts (William Roche) [Orabug: 29660924]

  - repairing out-of-tree build functionality (Mark
    Nicholson) [Orabug: 29755100]

  - ext4: fix false negatives*and* false positives in
    ext4_check_descriptors (Shuning Zhang) [Orabug:
    29797007]

  - ocfs2: fix ocfs2 read inode data panic in ocfs2_iget
    (Shuning Zhang) [Orabug: 29233739]

  - Bluetooth: Verify that l2cap_get_conf_opt provides large
    enough buffer (Marcel Holtmann) [Orabug: 29526426]
    (CVE-2019-3459)

  - Bluetooth: Check L2CAP option sizes returned from
    l2cap_get_conf_opt (Marcel Holtmann) [Orabug: 29526426]
    (CVE-2019-3459)

  - HID: debug: fix the ring buffer implementation (Vladis
    Dronov) [Orabug: 29629481] (CVE-2019-3819)
    (CVE-2019-3819)

  - scsi: target: iscsi: Use hex2bin instead of a
    re-implementation (Vincent Pelletier) [Orabug: 29778875]
    (CVE-2018-14633) (CVE-2018-14633)

  - scsi: libsas: fix a race condition when smp task timeout
    (Jason Yan) [Orabug: 29783225] (CVE-2018-20836)

  - scsi: megaraid_sas: return error when create DMA pool
    failed (Jason Yan) [Orabug: 29783254] (CVE-2019-11810)

  - Bluetooth: hidp: fix buffer overflow (Young Xiao)
    [Orabug: 29786786] (CVE-2011-1079) (CVE-2019-11884)

  - x86/speculation/mds: Add 'mitigations=' support for MDS
    (Kanth Ghatraju) [Orabug: 29791046]

  - net: rds: force to destroy connection if t_sock is NULL
    in rds_tcp_kill_sock. (Mao Wenan) [Orabug: 29802785]
    (CVE-2019-11815)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2019-June/000943.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.28.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.28.1.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
