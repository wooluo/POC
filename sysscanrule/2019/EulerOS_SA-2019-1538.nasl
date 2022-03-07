#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124991);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-6763",
    "CVE-2013-7339",
    "CVE-2014-0038",
    "CVE-2014-2039",
    "CVE-2015-1593",
    "CVE-2016-3070",
    "CVE-2016-6136",
    "CVE-2016-8650",
    "CVE-2017-15129",
    "CVE-2017-16994",
    "CVE-2017-18174",
    "CVE-2017-9059",
    "CVE-2018-10124",
    "CVE-2018-1118",
    "CVE-2018-3639",
    "CVE-2018-5848",
    "CVE-2018-7566",
    "CVE-2018-7754",
    "CVE-2019-8912",
    "CVE-2019-9003"
  );
  script_bugtraq_id(
    63707,
    65255,
    65700,
    66351,
    72607
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1538)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The walk_hugetlb_range() function in 'mm/pagewalk.c'
    file in the Linux kernel from v4.0-rc1 through
    v4.15-rc1 mishandles holes in hugetlb ranges. This
    allows local users to obtain sensitive information from
    uninitialized kernel memory via crafted use of the
    mincore() system call.(CVE-2017-16994)

  - In the Linux kernel before 4.7, the amd_gpio_remove
    function in drivers/pinctrl/pinctrl-amd.c calls the
    pinctrl_unregister function, leading to a double
    free.(CVE-2017-18174)

  - In the Linux kernel through 4.20.11, af_alg_release()
    in crypto/af_alg.c neglects to set a NULL value for a
    certain structure member, which leads to a
    use-after-free in sockfs_setattr.(CVE-2019-8912)

  - A security flaw was found in the Linux kernel that an
    attempt to move page mapped by AIO ring buffer to the
    other node triggers NULL pointer dereference at
    trace_writeback_dirty_page(), because
    aio_fs_backing_dev_info.dev is 0.(CVE-2016-3070)

  - The NFSv4 implementation in the Linux kernel through
    4.11.1 allows local users to cause a denial of service
    (resource consumption) by leveraging improper channel
    callback shutdown when unmounting an NFSv4 filesystem,
    aka a 'module reference and kernel daemon'
    leak.(CVE-2017-9059)

  - When creating audit records for parameters to executed
    children processes, an attacker can convince the Linux
    kernel audit subsystem can create corrupt records which
    may allow an attacker to misrepresent or evade logging
    of executing commands.(CVE-2016-6136)

  - A use-after-free vulnerability was found in a network
    namespaces code affecting the Linux kernel since
    v4.0-rc1 through v4.15-rc5. The function
    get_net_ns_by_id() does not check for the net::count
    value after it has found a peer network in netns_ids
    idr which could lead to double free and memory
    corruption. This vulnerability could allow an
    unprivileged local user to induce kernel memory
    corruption on the system, leading to a crash. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out, although it is thought to be
    unlikely.(CVE-2017-15129)

  - A NULL pointer dereference flaw was found in the
    rds_ib_laddr_check() function in the Linux kernel's
    implementation of Reliable Datagram Sockets (RDS). A
    local, unprivileged user could use this flaw to crash
    the system.(CVE-2013-7339)

  - A flaw was found in the Linux kernel key management
    subsystem in which a local attacker could crash the
    kernel or corrupt the stack and additional memory
    (denial of service) by supplying a specially crafted
    RSA key. This flaw panics the machine during the
    verification of the RSA key.(CVE-2016-8650)

  - The uio_mmap_physical function in drivers/uio/uio.c in
    the Linux kernel before 3.12 does not validate the size
    of a memory block, which allows local users to cause a
    denial of service (memory corruption) or possibly gain
    privileges via crafted mmap operations, a different
    vulnerability than CVE-2013-4511.(CVE-2013-6763)

  - In the Linux kernel before 4.20.5, attackers can
    trigger a drivers/char/ipmi/ipmi_msghandler.c
    use-after-free and OOPS by arranging for certain
    simultaneous execution of the code, as demonstrated by
    a 'service ipmievd restart' loop.(CVE-2019-9003)

  - An integer overflow flaw was found in the way the Linux
    kernel randomized the stack for processes on certain
    64-bit architecture systems, such as x86-64, causing
    the stack entropy to be reduced by four.(CVE-2015-1593)

  - The compat_sys_recvmmsg function in net/compat.c in the
    Linux kernel before 3.13.2, when CONFIG_X86_X32 is
    enabled, allows local users to gain privileges via a
    recvmmsg system call with a crafted timeout pointer
    parameter.(CVE-2014-0038)

  - The kill_something_info function in kernel/signal.c in
    the Linux kernel before 4.13, when an unspecified
    architecture and compiler is used, might allow local
    users to cause a denial of service via an INT_MIN
    argument.(CVE-2018-10124)

  - arch/s390/kernel/head64.S in the Linux kernel before
    3.13.5 on the s390 platform does not properly handle
    attempted use of the linkage stack, which allows local
    users to cause a denial of service (system crash) by
    executing a crafted instruction.(CVE-2014-2039)

  - A flaw was found in the Linux kernel in that the
    aoedisk_debugfs_show() function in
    drivers/block/aoe/aoeblk.c allows local users to obtain
    some kernel address information by reading a debugfs
    file. This address is not useful to commit a further
    attack.(CVE-2018-7754)

  - ALSA sequencer core initializes the event pool on
    demand by invoking snd_seq_pool_init() when the first
    write happens and the pool is empty. A user can reset
    the pool size manually via ioctl concurrently, and this
    may lead to UAF or out-of-bound access.(CVE-2018-7566)

  - In the function wmi_set_ie() in the Linux kernel the
    length validation code does not handle unsigned integer
    overflow properly. As a result, a large value of the
    'ie_len' argument can cause a buffer overflow and thus
    a memory corruption leading to a system crash or other
    or unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-5848)

  - The Linux kernel does not properly initialize memory in
    messages passed between virtual guests and the host
    operating system in the vhost/vhost.c:vhost_new_msg()
    function. This can allow local privileged users to read
    some kernel memory contents when reading from the
    /dev/vhost-net device file.(CVE-2018-1118)

  - Systems with microprocessors utilizing speculative
    execution and speculative execution of memory reads
    before the addresses of all prior memory writes are
    known may allow unauthorized disclosure of information
    to an attacker with local user access via a
    side-channel analysis, aka Speculative Store Bypass
    (SSB), Variant 4.(CVE-2018-3639)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1538
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel recvmmsg Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
