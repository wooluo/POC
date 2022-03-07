#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4713.
#

include("compat.inc");

if (description)
{
  script_id(126673);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/15 14:20:21");

  script_cve_id("CVE-2017-5931", "CVE-2017-6058", "CVE-2017-9524", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-20123", "CVE-2019-11091", "CVE-2019-12155");

  script_name(english:"Oracle Linux 7 : qemu (ELSA-2019-4713) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[15:3.1.0-5.el7]
- Only enable the halt poll control MSR if it is supported by the host (Mark
Kanda) [Orabug: 29946722]

[15:3.1.0-4.el7]
- kvm: i386: halt poll control MSR support (Marcelo Tosatti) [Orabug: 
29933278]
- Document CVEs as fixed: CVE-2017-9524, CVE-2017-6058, CVE-2017-5931 
(Mark Kanda) [Orabug: 29886908] {CVE-2017-5931} {CVE-2017-6058} 
{CVE-2017-9524}
- pvrdma: release device resources in case of an error (Prasad J Pandit) 
[Orabug: 29056678] {CVE-2018-20123}
- qxl: check release info object (Prasad J Pandit) [Orabug: 29886906] 
{CVE-2019-12155}
- target/i386: add MDS-NO feature (Paolo Bonzini) [Orabug: 29820428] 
{CVE-2018-12126} {CVE-2018-12127} {CVE-2018-12130} {CVE-2019-11091}
- docs: recommend use of md-clear feature on all Intel CPUs (Daniel P. 
Berrang&eacute ) [Orabug: 29820428] {CVE-2018-12126} {CVE-2018-12127} 
{CVE-2018-12130} {CVE-2019-11091}
- target/i386: define md-clear bit (Paolo Bonzini) [Orabug: 29820428] 
{CVE-2018-12126} {CVE-2018-12127} {CVE-2018-12130} {CVE-2019-11091}
- pvh: block migration if booting using PVH (Liam Merwick) [Orabug: 
29796676]
- hw/i386/pc: run the multiboot loader before the PVH loader (Stefano 
Garzarella) [Orabug: 29796676]
- optionrom/pvh: load initrd from fw_cfg (Stefano Garzarella) [Orabug: 
29796676]
- hw/i386/pc: use PVH option rom (Stefano Garzarella) [Orabug: 29796676]
- qemu.spec: add pvh.bin to %files (Liam Merwick) [Orabug: 29796676]
- optionrom: add new PVH option rom (Stefano Garzarella) [Orabug: 29796676]
- linuxboot_dma: move common functions in a new header (Stefano 
Garzarella) [Orabug: 29796676]
- linuxboot_dma: remove duplicate definitions of FW_CFG (Stefano 
Garzarella) [Orabug: 29796676]
- pvh: load initrd and expose it through fw_cfg (Stefano Garzarella) 
[Orabug: 29796676]
- pvh: Boot uncompressed kernel using direct boot ABI (Liam Merwick) 
[Orabug: 29796676]
- pvh: Add x86/HVM direct boot ABI header file (Liam Merwick) [Orabug: 
29796676]
- elf-ops.h: Add get_elf_note_type() (Liam Merwick) [Orabug: 29796676]
- elf: Add optional function ptr to load_elf() to parse ELF notes (Liam 
Merwick) [Orabug: 29796676]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-July/008891.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-block-gluster-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-block-iscsi-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-block-rbd-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-common-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-img-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-core-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-system-x86-3.1.0-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-system-x86-core-3.1.0-5.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu / qemu-block-gluster / qemu-block-iscsi / qemu-block-rbd / etc");
}
