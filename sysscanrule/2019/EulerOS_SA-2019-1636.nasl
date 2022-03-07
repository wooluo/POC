#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125588);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-7470",
    "CVE-2018-16880",
    "CVE-2018-19406",
    "CVE-2018-19985",
    "CVE-2019-11815",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3819",
    "CVE-2019-3837",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-3901",
    "CVE-2019-8956",
    "CVE-2019-9213"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2019-1636)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An issue was discovered in rds_tcp_kill_sock in
    net/rds/tcp.c in the Linux kernel before 5.0.8. There
    is a race condition leading to a use-after-free,
    related to net namespace cleanup.(CVE-2019-11815)

  - A flaw was found in the Linux kernel's handle_rx()
    function in the vhost_net driver. A malicious virtual
    guest, under specific conditions, can trigger an
    out-of-bounds write in a kmalloc-8 slab on a virtual
    host which may lead to a kernel memory corruption and a
    system panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out.(CVE-2018-16880)

  - A NULL pointer dereference security flaw was found in
    the Linux kernel in kvm_pv_send_ipi() in
    arch/x86/kvm/lapic.c. This allows local users with
    certain privileges to cause a denial of service via a
    crafted system call to the KVM
    subsystem.(CVE-2018-19406)

  - The function hso_get_config_data in
    drivers/net/usb/hso.c in the Linux kernel through
    4.19.8 reads if_num from the USB device (as a u8) and
    uses it to index a small array, resulting in an object
    out-of-bounds (OOB) read that potentially allows
    arbitrary read in the kernel address
    space.(CVE-2018-19985)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2019-3459)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2019-3460)

  - A flaw was found in the Linux kernel in the function
    hid_debug_events_read() in the drivers/hid/hid-debug.c
    file which may enter an infinite loop with certain
    parameters passed from a userspace. A local privileged
    user ('root') can cause a system lock up and a denial
    of service.(CVE-2019-3819)

  - In the Linux kernel before 4.20.14, expand_downwards in
    mm/mmap.c lacks a check for the mmap minimum address,
    which makes it easier for attackers to exploit kernel
    NULL pointer dereferences on non-SMAP platforms. This
    is related to a capability check for the wrong
    task.(CVE-2019-9213)

  - A flaw was found in the Linux kernel's vfio interface
    implementation that permits violation of the user's
    locked memory limit. If a device is bound to a vfio
    driver, such as vfio-pci, and the local attacker is
    administratively granted ownership of the device, it
    may cause a system memory exhaustion and thus a denial
    of service (DoS). Versions 3.10, 4.14 and 4.18 are
    vulnerable.(CVE-2019-3882)

  - An infinite loop issue was found in the vhost_net
    kernel module in Linux Kernel up to and including
    v5.1-rc6, while handling incoming packets in
    handle_rx(). It could occur if one end sends packets
    faster than the other end can process them. A guest
    user, maybe remote one, could use this flaw to stall
    the vhost_net kernel thread, resulting in a DoS
    scenario.(CVE-2019-3900)

  - It was found that the net_dma code in tcp_recvmsg() in
    the 2.6.32 kernel as shipped in RHEL6 is thread-unsafe.
    So an unprivileged multi-threaded userspace application
    calling recvmsg() for the same network socket in
    parallel executed on ioatdma-enabled hardware with
    net_dma enabled can leak the memory, crash the host
    leading to a denial-of-service or cause a random memory
    corruption.(CVE-2019-3837)

  - A race condition in perf_event_open() allows local
    attackers to leak sensitive data from setuid programs.
    As no relevant locks (in particular the
    cred_guard_mutex) are held during the
    ptrace_may_access() call, it is possible for the
    specified target task to perform an execve() syscall
    with setuid execution before perf_event_alloc()
    actually attaches to it, allowing an attacker to bypass
    the ptrace_may_access() check and the
    perf_event_exit_task(current) call that is performed in
    install_exec_creds() during privileged execve() calls.
    This issue affects kernel versions before 4.8.
    (CVE-2019-3901)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2019-8956)

  - cipso_v4_validate in include/net/cipso_ipv4.h in the
    Linux kernel before 3.11.7, when CONFIG_NETLABEL is
    disabled, allows attackers to cause a denial of service
    (infinite loop and crash), as demonstrated by icmpsic,
    a different vulnerability than
    CVE-2013-0310.(CVE-2013-7470)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1636
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-1.2.159",
        "kernel-devel-4.19.36-1.2.159",
        "kernel-headers-4.19.36-1.2.159",
        "kernel-tools-4.19.36-1.2.159",
        "kernel-tools-libs-4.19.36-1.2.159",
        "kernel-tools-libs-devel-4.19.36-1.2.159",
        "perf-4.19.36-1.2.159",
        "python-perf-4.19.36-1.2.159"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
