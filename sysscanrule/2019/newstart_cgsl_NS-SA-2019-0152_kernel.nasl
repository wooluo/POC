#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0152. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127425);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2012-6701",
    "CVE-2015-8830",
    "CVE-2016-6480",
    "CVE-2016-7042",
    "CVE-2016-7097",
    "CVE-2016-8399",
    "CVE-2016-8650",
    "CVE-2016-10142",
    "CVE-2017-0861",
    "CVE-2017-2671",
    "CVE-2017-6001",
    "CVE-2017-6214",
    "CVE-2017-7541",
    "CVE-2017-7542",
    "CVE-2017-7616",
    "CVE-2017-7889",
    "CVE-2017-9074",
    "CVE-2017-11176",
    "CVE-2017-12190",
    "CVE-2017-14106",
    "CVE-2017-15121",
    "CVE-2017-15265",
    "CVE-2017-18203",
    "CVE-2017-1000111",
    "CVE-2018-1130",
    "CVE-2018-3665",
    "CVE-2018-5803",
    "CVE-2018-7566",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2018-13405",
    "CVE-2018-1000004",
    "CVE-2019-11091"
  );
  script_bugtraq_id(102329, 106503);

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0152)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - It was found that AIO interface didn't use the proper
    rw_verify_area() helper function with extended
    functionality, for example, mandatory locking on the
    file. Also rw_verify_area() makes extended checks, for
    example, that the size of the access doesn't cause
    overflow of the provided offset limits. This integer
    overflow in fs/aio.c in the Linux kernel before 3.4.1
    allows local users to cause a denial of service or
    possibly have unspecified other impact via a large AIO
    iovec. (CVE-2012-6701)

  - Integer overflow in the aio_setup_single_vector function
    in fs/aio.c in the Linux kernel 4.0 allows local users
    to cause a denial of service or possibly have
    unspecified other impact via a large AIO iovec. NOTE:
    this vulnerability exists because of a CVE-2012-6701
    regression. (CVE-2015-8830)

  - It was discovered that a remote attacker could leverage
    the generation of IPv6 atomic fragments to trigger the
    use of fragmentation in an arbitrary IPv6 flow (in
    scenarios in which actual fragmentation of packets is
    not needed) and could subsequently perform any type of a
    fragmentation-based attack against legacy IPv6 nodes
    that do not implement RFC6946. (CVE-2016-10142)

  - A race condition flaw was found in the ioctl_send_fib()
    function in the Linux kernel's aacraid implementation. A
    local attacker could use this flaw to cause a denial of
    service (out-of-bounds access or system crash) by
    changing a certain size value. (CVE-2016-6480)

  - It was found that when the gcc stack protector was
    enabled, reading the /proc/keys file could cause a panic
    in the Linux kernel due to stack corruption. This
    happened because an incorrect buffer size was used to
    hold a 64-bit timeout value rendered as weeks.
    (CVE-2016-7042)

  - It was found that when file permissions were modified
    via chmod and the user modifying them was not in the
    owning group or capable of CAP_FSETID, the setgid bit
    would be cleared. Setting a POSIX ACL via setxattr sets
    the file permissions as well as the new ACL, but doesn't
    clear the setgid bit in a similar way. This could allow
    a local user to gain group privileges via certain setgid
    applications. (CVE-2016-7097)

  - A flaw was found in the Linux networking subsystem where
    a local attacker with CAP_NET_ADMIN capabilities could
    cause an out-of-bounds memory access by creating a
    smaller-than-expected ICMP header and sending to its
    destination via sendto(). (CVE-2016-8399)

  - A flaw was found in the Linux kernel key management
    subsystem in which a local attacker could crash the
    kernel or corrupt the stack and additional memory
    (denial of service) by supplying a specially crafted RSA
    key. This flaw panics the machine during the
    verification of the RSA key. (CVE-2016-8650)

  - Use-after-free vulnerability in the snd_pcm_info()
    function in the ALSA subsystem in the Linux kernel
    allows attackers to induce a kernel memory corruption
    and possibly crash or lock up a system. Due to the
    nature of the flaw, a privilege escalation cannot be
    fully ruled out, although we believe it is unlikely.
    (CVE-2017-0861)

  - A race condition issue was found in the way the raw
    packet socket implementation in the Linux kernel
    networking subsystem handled synchronization. A local
    user able to open a raw packet socket (requires the
    CAP_NET_RAW capability) could use this to waste
    resources in the kernel's ring buffer or possibly cause
    an out-of-bounds read on the heap leading to a system
    crash. (CVE-2017-1000111)

  - A use-after-free flaw was found in the Netlink
    functionality of the Linux kernel networking subsystem.
    Due to the insufficient cleanup in the mq_notify
    function, a local attacker could potentially use this
    flaw to escalate their privileges on the system.
    (CVE-2017-11176)

  - It was found that in the Linux kernel through v4.14-rc5,
    bio_map_user_iov() and bio_unmap_user() in 'block/bio.c'
    do unbalanced pages refcounting if IO vector has small
    consecutive buffers belonging to the same page.
    bio_add_pc_page() merges them into one, but the page
    reference is never dropped, causing a memory leak and
    possible system lockup due to out-of-memory condition.
    (CVE-2017-12190)

  - A divide-by-zero vulnerability was found in the
    __tcp_select_window function in the Linux kernel. This
    can result in a kernel panic causing a local denial of
    service. (CVE-2017-14106)

  - A non-privileged user is able to mount a fuse filesystem
    on RHEL 6 or 7 and crash a system if an application
    punches a hole in a file that does not end aligned to a
    page boundary. (CVE-2017-15121)

  - A use-after-free vulnerability was found when issuing an
    ioctl to a sound device. This could allow a user to
    exploit a race condition and create memory corruption or
    possibly privilege escalation. (CVE-2017-15265)

  - The Linux kernel, before version 4.14.3, is vulnerable
    to a denial of service in
    drivers/md/dm.c:dm_get_from_kobject() which can be
    caused by local users leveraging a race condition with
    __dm_destroy() during creation and removal of DM
    devices. Only privileged local users (with CAP_SYS_ADMIN
    capability) can directly perform the ioctl operations
    for dm device creation and removal and this would
    typically be outside the direct control of the
    unprivileged attacker. (CVE-2017-18203)

  - A race condition leading to a NULL pointer dereference
    was found in the Linux kernel's Link Layer Control
    implementation. A local attacker with access to ping
    sockets could use this flaw to crash the system.
    (CVE-2017-2671)

  - It was found that the original fix for CVE-2016-6786 was
    incomplete. There exist a race between two concurrent
    sys_perf_event_open() calls when both try and move the
    same pre-existing software group into a hardware
    context. (CVE-2017-6001)

  - A flaw was found in the Linux kernel's handling of
    packets with the URG flag. Applications using the
    splice() and tcp_splice_read() functionality could allow
    a remote attacker to force the kernel to enter a
    condition in which it could loop indefinitely.
    (CVE-2017-6214)

  - Kernel memory corruption due to a buffer overflow was
    found in brcmf_cfg80211_mgmt_tx() function in Linux
    kernels from v3.9-rc1 to v4.13-rc1. The vulnerability
    can be triggered by sending a crafted NL80211_CMD_FRAME
    packet via netlink. This flaw is unlikely to be
    triggered remotely as certain userspace code is needed
    for this. An unprivileged local user could use this flaw
    to induce kernel memory corruption on the system,
    leading to a crash. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out, although
    it is unlikely. (CVE-2017-7541)

  - An integer overflow vulnerability in
    ip6_find_1stfragopt() function was found. A local
    attacker that has privileges (of CAP_NET_RAW) to open
    raw socket can cause an infinite loop inside the
    ip6_find_1stfragopt() function. (CVE-2017-7542)

  - Incorrect error handling in the set_mempolicy() and
    mbind() compat syscalls in 'mm/mempolicy.c' in the Linux
    kernel allows local users to obtain sensitive
    information from uninitialized stack data by triggering
    failure of a certain bitmap operation. (CVE-2017-7616)

  - The mm subsystem in the Linux kernel through 4.10.10
    does not properly enforce the CONFIG_STRICT_DEVMEM
    protection mechanism, which allows local users to read
    or write to kernel memory locations in the first
    megabyte (and bypass slab-allocation access
    restrictions) via an application that opens the /dev/mem
    file, related to arch/x86/mm/init.c and
    drivers/char/mem.c. (CVE-2017-7889)

  - The IPv6 fragmentation implementation in the Linux
    kernel does not consider that the nexthdr field may be
    associated with an invalid option, which allows local
    users to cause a denial of service (out-of-bounds read
    and BUG) or possibly have unspecified other impact via
    crafted socket and send system calls. Due to the nature
    of the flaw, privilege escalation cannot be fully ruled
    out, although we believe it is unlikely. (CVE-2017-9074)

  - In the Linux kernel versions 4.12, 3.10, 2.6, and
    possibly earlier, a race condition vulnerability exists
    in the sound system allowing for a potential deadlock
    and memory corruption due to use-after-free condition
    and thus denial of service. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely. (CVE-2018-1000004)

  - A null pointer dereference in dccp_write_xmit() function
    in net/dccp/output.c in the Linux kernel allows a local
    user to cause a denial of service by a number of certain
    crafted system calls. (CVE-2018-1130)

  - Modern Intel microprocessors implement hardware-level
    micro-optimizations to improve the performance of
    writing data back to CPU caches. The write operation is
    split into STA (STore Address) and STD (STore Data) sub-
    operations. These sub-operations allow the processor to
    hand-off address generation logic into these sub-
    operations for optimized writes. Both of these sub-
    operations write to a shared distributed processor
    structure called the 'processor store buffer'. As a
    result, an unprivileged attacker could use this flaw to
    read private data resident within the CPU's processor
    store buffer. (CVE-2018-12126)

  - Microprocessors use a load port subcomponent to
    perform load operations from memory or IO. During a load
    operation, the load port receives data from the memory
    or IO subsystem and then provides the data to the CPU
    registers and operations in the CPUs pipelines. Stale
    load operations results are stored in the 'load port'
    table until overwritten by newer operations. Certain
    load-port operations triggered by an attacker can be
    used to reveal data about previous stale requests
    leaking data back to the attacker via a timing side-
    channel. (CVE-2018-12127)

  - A flaw was found in the implementation of the fill
    buffer, a mechanism used by modern CPUs when a cache-
    miss is made on L1 CPU cache. If an attacker can
    generate a load operation that would create a page
    fault, the execution will continue speculatively with
    incorrect data from the fill buffer while the data is
    fetched from higher level caches. This response time can
    be measured to infer data in the fill buffer.
    (CVE-2018-12130)

  - A vulnerability was found in the
    fs/inode.c:inode_init_owner() function logic of the
    LInux kernel that allows local users to create files
    with an unintended group ownership and with group
    execution and SGID permission bits set, in a scenario
    where a directory is SGID and belongs to a certain group
    and is writable by a user who is not a member of this
    group. This can lead to excessive permissions granted in
    case when they should not. (CVE-2018-13405)

  - A Floating Point Unit (FPU) state information leakage
    flaw was found in the way the Linux kernel saved and
    restored the FPU state during task switch. Linux kernels
    that follow the Lazy FPU Restore scheme are vulnerable
    to the FPU state information leakage issue. An
    unprivileged local attacker could use this flaw to read
    FPU state bits by conducting targeted cache side-channel
    attacks, similar to the Meltdown vulnerability disclosed
    earlier this year. (CVE-2018-3665)

  - An error in the _sctp_make_chunk() function
    (net/sctp/sm_make_chunk.c) when handling SCTP, packet
    length can be exploited by a malicious local user to
    cause a kernel crash and a DoS. (CVE-2018-5803)

  - ALSA sequencer core initializes the event pool on demand
    by invoking snd_seq_pool_init() when the first write
    happens and the pool is empty. A user can reset the pool
    size manually via ioctl concurrently, and this may lead
    to UAF or out-of-bound access. (CVE-2018-7566)

  - Uncacheable memory on some microprocessors utilizing
    speculative execution may allow an authenticated user to
    potentially enable information disclosure via a side
    channel with local access. (CVE-2019-11091)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0152");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6001");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "kernel-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-debug-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-debug-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-debuginfo-common-x86_64-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-devel-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-doc-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-firmware-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "kernel-headers-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "perf-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "python-perf-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030",
    "python-perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.129.gee87030"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
