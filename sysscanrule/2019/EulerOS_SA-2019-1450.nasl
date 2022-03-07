#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124953);
  script_version("1.7");
  script_cvs_date("Date: 2019/07/11 12:05:35");

  script_cve_id(
    "CVE-2016-3713",
    "CVE-2016-8630",
    "CVE-2017-1000252",
    "CVE-2017-17741",
    "CVE-2017-2583",
    "CVE-2017-2584",
    "CVE-2017-5715",
    "CVE-2017-7518",
    "CVE-2018-10853",
    "CVE-2018-3639",
    "CVE-2019-6974",
    "CVE-2019-7221",
    "CVE-2019-7222"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kvm (EulerOS-SA-2019-1450)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kvm package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - The msr_mtrr_valid function in arch/x86/kvm/mtrr.c in
    the Linux kernel before 4.6.1 supports MSR 0x2f8, which
    allows guest OS users to read or write to the
    kvm_arch_vcpu data structure, and consequently obtain
    sensitive information or cause a denial of service
    (system crash), via a crafted ioctl
    call.(CVE-2016-3713)

  - Linux kernel built with the Kernel-based Virtual
    Machine (CONFIG_KVM) support is vulnerable to a null
    pointer dereference flaw. It could occur on x86
    platform, when emulating an undefined instruction. An
    attacker could use this flaw to crash the host kernel
    resulting in DoS.(CVE-2016-8630)

  - Linux kernel built with the Kernel-based Virtual
    Machine (CONFIG_KVM) support was vulnerable to an
    incorrect segment selector(SS) value error. The error
    could occur while loading values into the SS register
    in long mode. A user or process inside a guest could
    use this flaw to crash the guest, resulting in DoS or
    potentially escalate their privileges inside the
    guest.(CVE-2017-2583)

  - arch/x86/kvm/emulate.c in the Linux kernel through
    4.9.3 allows local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (use-after-free) via a crafted application that
    leverages instruction emulation for fxrstor, fxsave,
    sgdt, and sidt.(CVE-2017-2584)

  - A reachable assertion failure flaw was found in the
    Linux kernel built with KVM virtualisation(CONFIG_KVM)
    support with Virtual Function I/O feature (CONFIG_VFIO)
    enabled. This failure could occur if a malicious guest
    device sent a virtual interrupt (guest IRQ) with a
    larger (>1024) index value.(CVE-2017-1000252)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5715 triggers the
    speculative execution by utilizing branch target
    injection. It relies on the presence of a
    precisely-defined instruction sequence in the
    privileged code as well as the fact that memory
    accesses may cause allocation into the microprocessor's
    data cache even for speculatively executed instructions
    that never actually commit (retire). As a result, an
    unprivileged attacker could use this flaw to cross the
    syscall and guest/host boundaries and read privileged
    memory by conducting targeted cache side-channel
    attacks.(CVE-2017-5715)

  - A flaw was found in the way the Linux KVM module
    processed the trap flag(TF) bit in EFLAGS during
    emulation of the syscall instruction, which leads to a
    debug exception(#DB) being raised in the guest stack. A
    user/process inside a guest could use this flaw to
    potentially escalate their privileges inside the guest.
    Linux guests are not affected by this.(CVE-2017-7518)

  - Linux kernel compiled with the KVM virtualization
    (CONFIG_KVM) support is vulnerable to an out-of-bounds
    read access issue. It could occur when emulating vmcall
    instructions invoked by a guest. A guest user/process
    could use this flaw to disclose kernel memory
    bytes.(CVE-2017-17741)

  - Systems with microprocessors utilizing speculative
    execution and speculative execution of memory reads
    before the addresses of all prior memory writes are
    known may allow unauthorized disclosure of information
    to an attacker with local user access via a
    side-channel analysis, aka Speculative Store Bypass
    (SSB), Variant 4.(CVE-2018-3639)

  - kernel: kvm: guest userspace to guest kernel
    write(CVE-2018-10853)

  - In the Linux kernel before 4.20.8,
    kvm_ioctl_create_device in virt/kvm/kvm_main.c
    mishandles reference counting because of a race
    condition, leading to a use-after-free.(CVE-2019-6974)

  - The KVM implementation in the Linux kernel through
    4.20.5 has an Information Leak.(CVE-2019-7222)

  - The KVM implementation in the Linux kernel through
    4.20.5 has a Use-after-Free.(CVE-2019-7221)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1450
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kvm-4.4.11-30.011"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
