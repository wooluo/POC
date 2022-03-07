#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124398);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2018-10876",
    "CVE-2018-10882",
    "CVE-2018-16862",
    "CVE-2018-19985",
    "CVE-2018-9568",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-5489",
    "CVE-2019-7221",
    "CVE-2019-9213"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2019-1302)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Linux kernel's ext4 filesystem
    code. A use-after-free is possible in
    ext4_ext_remove_space() function when mounting and
    operating a crafted ext4 image.(CVE-2018-10876)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound write in the
    fs/jbd2/transaction.c code, a denial of service, and a
    system crash by unmounting a crafted ext4 filesystem
    image.(CVE-2018-10882)

  - A use-after-free vulnerability was found in the way the
    Linux kernel's KVM hypervisor emulates a preemption
    timer for L2 guests when nested (=1) virtualization is
    enabled. This high resolution timer(hrtimer) runs when
    a L2 guest is active. After VM exit, the sync_vmcs12()
    timer object is stopped. The use-after-free occurs if
    the timer object is freed before calling sync_vmcs12()
    routine. A guest user/process could use this flaw to
    crash the host kernel resulting in a denial of service
    or, potentially, gain privileged access to a
    system.(CVE-2019-7221)

  - A flaw was found in the Linux kernel in the function
    hso_probe() which reads if_num value from the USB
    device (as an u8) and uses it without a length check to
    index an array, resulting in an OOB memory read in
    hso_probe() or hso_get_config_data(). An attacker with
    a forged USB device and physical access to a system
    (needed to connect such a device) can cause a system
    crash and a denial of service.(CVE-2018-19985)

  - A possible memory corruption due to a type confusion
    was found in the Linux kernel in the sk_clone_lock()
    function in the net/core/sock.c. The possibility of
    local escalation of privileges cannot be fully ruled
    out for a local unprivileged attacker.(CVE-2018-9568)

  - A flaw was found in the Linux kernels implementation of
    Logical link control and adaptation protocol (L2CAP),
    part of the Bluetooth stack. An attacker with physical
    access within the range of standard Bluetooth
    transmission can create a specially crafted packet. The
    response to this specially crafted packet can contain
    part of the kernel stack which can be used in a further
    attack.(CVE-2019-3459)

  - A flaw was found in the Linux kernel's implementation
    of logical link control and adaptation protocol
    (L2CAP), part of the Bluetooth stack in the
    l2cap_parse_conf_rsp and l2cap_parse_conf_req
    functions. An attacker with physical access within the
    range of standard Bluetooth transmission can create a
    specially crafted packet. The response to this
    specially crafted packet can contain part of the kernel
    stack which can be used in a further
    attack.(CVE-2019-3460)

  - A flaw was found in mmap in the Linux kernel allowing
    the process to map a null page. This allows attackers
    to abuse this mechanism to turn null pointer
    dereferences into workable exploits(CVE-2019-9213)

  - A new software page cache side channel attack scenario
    was discovered in operating systems that implement the
    very common 'page cache' caching mechanism. A malicious
    user/process could use 'in memory' page-cache knowledge
    to infer access timings to shared memory and gain
    knowledge which can be used to reduce effectiveness of
    cryptographic strength by monitoring algorithmic
    behavior, infer access patterns of memory to determine
    code paths taken, and exfiltrate data to a blinded
    attacker through page-granularity access times as a
    side-channel.(CVE-2019-5489)

  - A security flaw was found in the Linux kernel in a way
    that the cleancache subsystem clears an inode after the
    final file truncation (removal). The new file created
    with the same inode may contain leftover pages from
    cleancache and the old file data instead of the new
    one.(CVE-2018-16862)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1302
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.62.59.83.h149",
        "kernel-debug-3.10.0-327.62.59.83.h149",
        "kernel-debug-devel-3.10.0-327.62.59.83.h149",
        "kernel-debuginfo-3.10.0-327.62.59.83.h149",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h149",
        "kernel-devel-3.10.0-327.62.59.83.h149",
        "kernel-headers-3.10.0-327.62.59.83.h149",
        "kernel-tools-3.10.0-327.62.59.83.h149",
        "kernel-tools-libs-3.10.0-327.62.59.83.h149",
        "perf-3.10.0-327.62.59.83.h149",
        "python-perf-3.10.0-327.62.59.83.h149"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
