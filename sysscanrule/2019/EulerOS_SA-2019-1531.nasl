#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124984);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-4343",
    "CVE-2013-4511",
    "CVE-2014-4171",
    "CVE-2014-5077",
    "CVE-2015-5156",
    "CVE-2015-6252",
    "CVE-2016-2068",
    "CVE-2016-7042",
    "CVE-2016-9919",
    "CVE-2017-12190",
    "CVE-2017-18224",
    "CVE-2017-7277",
    "CVE-2017-7477",
    "CVE-2017-9075",
    "CVE-2018-1095",
    "CVE-2018-13405",
    "CVE-2018-18397",
    "CVE-2018-19854",
    "CVE-2018-6412",
    "CVE-2019-6974"
  );
  script_bugtraq_id(
    62360,
    63512,
    68157,
    68881
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1531)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Use-after-free vulnerability in drivers/net/tun.c in
    the Linux kernel through 3.11.1 allows local users to
    gain privileges by leveraging the CAP_NET_ADMIN
    capability and providing an invalid tuntap interface
    name in a TUNSETIFF ioctl call.(CVE-2013-4343)

  - It was found that when the gcc stack protector was
    enabled, reading the /proc/keys file could cause a
    panic in the Linux kernel due to stack corruption. This
    happened because an incorrect buffer size was used to
    hold a 64-bit timeout value rendered as
    weeks.(CVE-2016-7042)

  - A flaw was found in the Linux kernel that
    fs/ocfs2/aops.c omits use of a semaphore and
    consequently has a race condition for access to the
    extent tree during read operations in DIRECT mode. This
    allows local users to cause a denial of service by
    modifying a certain e_cpos field.(CVE-2017-18224)

  - The sctp_v6_create_accept_sk function in
    net/sctp/ipv6.c in the Linux kernel mishandles
    inheritance, which allows local users to cause a denial
    of service or possibly have unspecified other impact
    via crafted system calls, a related issue to
    CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-9075)

  - In the function sbusfb_ioctl_helper() in
    drivers/video/fbdev/sbuslib.c in the Linux kernel, up
    to and including 4.15, an integer signedness error
    allows arbitrary information leakage for the
    FBIOPUTCMAP_SPARC and FBIOGETCMAP_SPARC
    commands.(CVE-2018-6412)

  - A race condition flaw was found in the way the Linux
    kernel's mmap(2), madvise(2), and fallocate(2) system
    calls interacted with each other while operating on
    virtual memory file system files. A local user could
    use this flaw to cause a denial of
    service.(CVE-2014-4171)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2018-1095)

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's Stream Control Transmission Protocol
    (SCTP) implementation handled simultaneous connections
    between the same hosts. A remote attacker could use
    this flaw to crash the system.(CVE-2014-5077)

  - A vulnerability was found in the
    fs/inode.c:inode_init_owner() function logic of the
    LInux kernel that allows local users to create files
    with an unintended group ownership and with group
    execution and SGID permission bits set, in a scenario
    where a directory is SGID and belongs to a certain
    group and is writable by a user who is not a member of
    this group. This can lead to excessive permissions
    granted in case when they should not.(CVE-2018-13405)

  - In the Linux kernel before 4.20.8,
    kvm_ioctl_create_device in virt/kvm/kvm_main.c
    mishandles reference counting because of a race
    condition, leading to a use-after-free.(CVE-2019-6974)

  - A flaw was found in the way Linux kernel allocates heap
    memory to build the scattergather list from a fragment
    list(skb_shinfo(skb)->frag_list) in the socket
    buffer(skb_buff). The heap overflow occurred if
    'MAX_SKB_FRAGS + 1' parameter and 'NETIF_F_FRAGLIST'
    feature are both used together. A remote user or
    process could use this flaw to potentially escalate
    their privilege on a system.(CVE-2017-7477)

  - Multiple integer overflows in Alchemy LCD frame-buffer
    drivers in the Linux kernel before 3.12 allow local
    users to create a read-write memory mapping for the
    entirety of kernel memory, and consequently gain
    privileges, via crafted mmap operations, related to the
    (1) au1100fb_fb_mmap function in
    drivers/video/au1100fb.c and the (2) au1200fb_fb_mmap
    function in drivers/video/au1200fb.c.(CVE-2013-4511)

  - It was found that in the Linux kernel through
    v4.14-rc5, bio_map_user_iov() and bio_unmap_user() in
    'block/bio.c' do unbalanced pages refcounting if IO
    vector has small consecutive buffers belonging to the
    same page. bio_add_pc_page() merges them into one, but
    the page reference is never dropped, causing a memory
    leak and possible system lockup due to out-of-memory
    condition.(CVE-2017-12190)

  - An issue was discovered in the Linux kernel before
    4.19.3. crypto_report_one() and related functions in
    crypto/crypto_user.c (the crypto user configuration
    API) do not fully initialize structures that are copied
    to userspace, potentially leaking sensitive memory to
    user programs. NOTE: this is a CVE-2013-2547 regression
    but with easier exploitability because the attacker
    does not need a capability (however, the system must
    have the CONFIG_CRYPTO_USER kconfig
    option).(CVE-2018-19854)

  - The userfaultfd implementation in the Linux kernel
    before 4.19.7 mishandles access control for certain
    UFFDIO_ ioctl calls, as demonstrated by allowing local
    users to write data into holes in a tmpfs file (if the
    user has read-only access to that file, and that file
    contains holes), related to fs/userfaultfd.c and
    mm/userfaultfd.c.(CVE-2018-18397)

  - The TCP stack in the Linux kernel through 4.10.6
    mishandles the SCM_TIMESTAMPING_OPT_STATS feature,
    which allows local users to obtain sensitive
    information from the kernel's internal socket data
    structures or cause a denial of service (out-of-bounds
    read) via crafted system calls, related to
    net/core/skbuff.c and net/socket.c.(CVE-2017-7277)

  - A flaw was found in the way the Linux kernel's vhost
    driver treated userspace provided log file descriptor
    when processing the VHOST_SET_LOG_FD ioctl command. The
    file descriptor was never released and continued to
    consume kernel memory. A privileged local user with
    access to the /dev/vhost-net files could use this flaw
    to create a denial-of-service attack.(CVE-2015-6252)

  - A buffer overflow flaw was found in the way the Linux
    kernel's virtio-net subsystem handled certain fraglists
    when the GRO (Generic Receive Offload) functionality
    was enabled in a bridged network configuration. An
    attacker on the local network could potentially use
    this flaw to crash the system, or, although unlikely,
    elevate their privileges on the system.(CVE-2015-5156)

  - The MSM QDSP6 audio driver (aka sound driver) for the
    Linux kernel 3.x, as used in Qualcomm Innovation Center
    (QuIC) Android contributions for MSM devices and other
    products, allows attackers to gain privileges or cause
    a denial of service (integer overflow, and buffer
    overflow or buffer over-read) via a crafted application
    that performs a (1) AUDIO_EFFECTS_WRITE or (2)
    AUDIO_EFFECTS_READ operation, aka Qualcomm internal bug
    CR1006609.(CVE-2016-2068)

  - The icmp6_send function in net/ipv6/icmp.c in the Linux
    kernel through 4.8.12 omits a certain check of the dst
    data structure which allows remote attackers to cause a
    denial of service (panic) via a fragmented IPv6
    packet.(CVE-2016-9919)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1531
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
