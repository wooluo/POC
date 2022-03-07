#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124985);
  script_version("1.7");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id(
    "CVE-2013-2894",
    "CVE-2013-2930",
    "CVE-2014-4652",
    "CVE-2014-8133",
    "CVE-2014-9644",
    "CVE-2015-6526",
    "CVE-2015-8215",
    "CVE-2016-4470",
    "CVE-2016-4565",
    "CVE-2016-4913",
    "CVE-2016-6198",
    "CVE-2016-7097",
    "CVE-2017-15274",
    "CVE-2017-16995",
    "CVE-2017-17864",
    "CVE-2017-6001",
    "CVE-2018-14610",
    "CVE-2018-7757",
    "CVE-2019-5489",
    "CVE-2019-9162"
  );
  script_bugtraq_id(
    62052,
    64318,
    68170,
    71684,
    72320
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1532)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in the way the Linux kernel's perf
    subsystem retrieved userlevel stack traces on PowerPC
    systems. A local, unprivileged user could use this flaw
    to cause a denial of service on the system by creating
    a special stack layout that would force the
    perf_callchain_user_64() function into an infinite
    loop.(CVE-2015-6526)

  - A vulnerability was found in the Linux kernel. Payloads
    of NM entries are not supposed to contain NUL. When
    such entry is processed, only the part prior to the
    first NUL goes into the concatenation (i.e. the
    directory entry name being encoded by a bunch of NM
    entries). The process stops when the amount collected
    so far + the claimed amount in the current NM entry
    exceed 254. However, the value returned as the total
    length is the sum of *claimed* sizes, not the actual
    amount collected. And that's what will be passed to
    readdir() callback as the name length - 8Kb
    __copy_to_user() from a buffer allocated by
    __get_free_page().(CVE-2016-4913)

  - The perf_trace_event_perm function in
    kernel/trace/trace_event_perf.c in the Linux kernel
    before 3.12.2 does not properly restrict access to the
    perf subsystem, which allows local users to enable
    function tracing via a crafted
    application.(CVE-2013-2930)

  - The mincore() implementation in mm/mincore.c in the
    Linux kernel through 4.19.13 allowed local attackers to
    observe page cache access patterns of other processes
    on the same system, potentially allowing sniffing of
    secret information. (Fixing this affects the output of
    the fincore program.) Limited remote exploitation may
    be possible, as demonstrated by latency differences in
    accessing public files from an Apache HTTP
    Server.(CVE-2019-5489)

  - It was found that the espfix functionality could be
    bypassed by installing a 16-bit RW data segment into
    GDT instead of LDT (which espfix checks), and using
    that segment on the stack. A local, unprivileged user
    could potentially use this flaw to leak kernel stack
    addresses.(CVE-2014-8133)

  - An issue was discovered in the btrfs filesystem code in
    the Linux kernel. An out-of-bounds access is possible
    in write_extent_buffer() when mounting and operating a
    crafted btrfs image due to a lack of verification at
    mount time within the btrfs_read_block_groups() in
    fs/btrfs/extent-tree.c function. This could lead to a
    system crash and a denial of service.(CVE-2018-14610)

  - kernel/bpf/verifier.c in the Linux kernel through
    4.14.8 mishandles states_equal comparisons between the
    pointer data type and the UNKNOWN_VALUE data type,
    which allows local users to obtain potentially
    sensitive address information, aka a 'pointer
    leak.'(CVE-2017-17864)

  - drivers/hid/hid-lenovo-tpkbd.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_LENOVO_TPKBD is enabled, allows
    physically proximate attackers to cause a denial of
    service (heap-based out-of-bounds write) via a crafted
    device.(CVE-2013-2894)

  - Memory leak in the sas_smp_get_phy_events function in
    drivers/scsi/libsas/sas_expander.c in the Linux kernel
    allows local users to cause a denial of service (kernel
    memory exhaustion) via multiple read accesses to files
    in the /sys/class/sas_phy directory.(CVE-2018-7757)

  - It was found that the original fix for CVE-2016-6786
    was incomplete. There exist a race between two
    concurrent sys_perf_event_open() calls when both try
    and move the same pre-existing software group into a
    hardware context.(CVE-2017-6001)

  - In the Linux kernel before 4.20.12,
    net/ipv4/netfilter/nf_nat_snmp_basic_main.c in the SNMP
    NAT module has insufficient ASN.1 length checks (aka an
    array index error), making out-of-bounds read and write
    operations possible, leading to an OOPS or local
    privilege escalation. This affects snmp_version and
    snmp_helper.(CVE-2019-9162)

  - An information leak flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled access of the user control's
    state. A local, privileged user could use this flaw to
    leak kernel memory to user space.(CVE-2014-4652)

  - A flaw was found that the vfs_rename() function did not
    detect hard links on overlayfs. A local, unprivileged
    user could use the rename syscall on overlayfs on top
    of xfs to crash the system.(CVE-2016-6198)

  - It was found that when file permissions were modified
    via chmod and the user modifying them was not in the
    owning group or capable of CAP_FSETID, the setgid bit
    would be cleared. Setting a POSIX ACL via setxattr sets
    the file permissions as well as the new ACL, but
    doesn't clear the setgid bit in a similar way. This
    could allow a local user to gain group privileges via
    certain setgid applications.(CVE-2016-7097)

  - A flaw was found in the way the Linux kernel's Crypto
    subsystem handled automatic loading of kernel modules.
    A local user could use this flaw to load any installed
    kernel module, and thus increase the attack surface of
    the running kernel.(CVE-2014-9644)

  - An arbitrary memory r/w access issue was found in the
    Linux kernel compiled with the eBPF bpf(2) system call
    (CONFIG_BPF_SYSCALL) support. The issue could occur due
    to calculation errors in the eBPF verifier module,
    triggered by user supplied malicious BPF program. An
    unprivileged user could use this flaw to escalate their
    privileges on a system. Setting parameter
    'kernel.unprivileged_bpf_disabled=1' prevents such
    privilege escalation by restricting access to bpf(2)
    call.(CVE-2017-16995)

  - A flaw was found in the implementation of associative
    arrays where the add_key systemcall and KEYCTL_UPDATE
    operations allowed for a NULL payload with a nonzero
    length. When accessing the payload within this length
    parameters value, an unprivileged user could trivially
    cause a NULL pointer dereference (kernel
    oops).(CVE-2017-15274)

  - A flaw was found in the Linux kernel's keyring handling
    code: the key_reject_and_link() function could be
    forced to free an arbitrary memory block. An attacker
    could use this flaw to trigger a use-after-free
    condition on the system, potentially allowing for
    privilege escalation.(CVE-2016-4470)

  - A flaw was found in the way certain interfaces of the
    Linux kernel's Infiniband subsystem used write() as
    bi-directional ioctl() replacement, which could lead to
    insufficient memory security checks when being invoked
    using the splice() system call. A local unprivileged
    user on a system with either Infiniband hardware
    present or RDMA Userspace Connection Manager Access
    module explicitly loaded, could use this flaw to
    escalate their privileges on the system.(CVE-2016-4565)

  - It was found that the Linux kernel's IPv6 network stack
    did not properly validate the value of the MTU variable
    when it was set. A remote attacker could potentially
    use this flaw to disrupt a target system's networking
    (packet loss) by setting an invalid MTU value, for
    example, via a NetworkManager daemon that is processing
    router advertisement packets running on the target
    system.(CVE-2015-8215)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1532
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BPF Sign Extension Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

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
