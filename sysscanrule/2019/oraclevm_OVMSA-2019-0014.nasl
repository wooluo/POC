#
# (C) WebRAY Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0014.
#

include("compat.inc");

if (description)
{
  script_id(124637);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/06 10:10:17");

  script_cve_id("CVE-2018-1066", "CVE-2018-10881", "CVE-2018-10882", "CVE-2019-3701");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0014)");
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

  - ib_core: initialize shpd field when allocating 'struct
    ib_pd' (Mukesh Kacker) [Orabug: 29384815]

  - Revert 'x86/apic: Make arch_setup_hwirq NUMA node aware'
    (Brian Maly) [Orabug: 29542185]

  - qlcnic: fix Tx descriptor corruption on 82xx devices
    (Shahed Shaikh) [Orabug: 27708787]

  - block: Fix a race between blk_cleanup_queue and timeout
    handling (Bart Van Assche) [Orabug: 29158186]

  - can: gw: ensure DLC boundaries after CAN frame
    modification (Oliver Hartkopp) [Orabug: 29215299]
    (CVE-2019-3701) (CVE-2019-3701)

  - CIFS: Enable encryption during session setup phase
    (Pavel Shilovsky) [Orabug: 29338239] (CVE-2018-1066)

  - ext4: clear i_data in ext4_inode_info when removing
    inline data (Theodore Ts'o) [Orabug: 29540709]
    (CVE-2018-10881) (CVE-2018-10881)

  - ext4: add more inode number paranoia checks (Theodore
    Ts'o) [Orabug: 29545566] (CVE-2018-10882)
    (CVE-2018-10882)

  - Revert 'KVM: nVMX: Eliminate vmcs02 pool' (Boris
    Ostrovsky) [Orabug: 29542029]

  - Revert 'KVM: VMX: introduce alloc_loaded_vmcs' (Boris
    Ostrovsky) [Orabug: 29542029]

  - Revert 'KVM: VMX: make MSR bitmaps per-VCPU' (Boris
    Ostrovsky) [Orabug: 29542029]

  - Revert 'KVM: x86: pass host_initiated to functions that
    read MSRs' (Boris Ostrovsky) [Orabug: 29542029]

  - Revert 'KVM/x86: Add IBPB support' (Boris Ostrovsky)
    [Orabug: 29542029]

  - Revert 'KVM/VMX: Allow direct access to
    MSR_IA32_SPEC_CTRL - reloaded' (Boris Ostrovsky)
    [Orabug: 29542029]

  - Revert 'KVM/SVM: Allow direct access to
    MSR_IA32_SPEC_CTRL' (Boris Ostrovsky) [Orabug: 29542029]

  - Revert 'KVM: SVM: Add MSR-based feature support for
    serializing LFENCE' (Boris Ostrovsky) [Orabug: 29542029]

  - Revert 'x86/cpufeatures: rename X86_FEATURE_AMD_SSBD to
    X86_FEATURE_LS_CFG_SSBD' (Boris Ostrovsky) [Orabug:
    29542029]

  - Revert 'x86/bugs: Add AMD's SPEC_CTRL MSR usage' (Boris
    Ostrovsky) [Orabug: 29542029]

  - Revert 'x86/bugs: Fix the AMD SSBD usage of the
    SPEC_CTRL MSR' (Boris Ostrovsky) [Orabug: 29542029]

  - arch: x86: remove unsued SET_IBPB from spec_ctrl.h
    (Mihai Carabas) [Orabug: 29336760]

  - x86: cpu: microcode: fix late loading SpectreV2 bugs
    eval (Mihai Carabas) [Orabug: 29336760]

  - x86: cpu: microcode: fix late loading SSBD and L1TF bugs
    eval (Mihai Carabas) [Orabug: 29336760]

  - x86: cpu: microcode: Re-evaluate bugs in a CPU after
    microcode loading (Mihai Carabas) [Orabug: 29336760]

  - x86: cpu: microcode: update flags for all cpus (Mihai
    Carabas) [Orabug: 29336760]

  - x86/apic: Make arch_setup_hwirq NUMA node aware (Henry
    Willard) [Orabug: 29292411]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2019-May/000936.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/06");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.26.7.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.26.7.el6uek")) flag++;

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
