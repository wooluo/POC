#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124979);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2010-5321",
    "CVE-2013-2896",
    "CVE-2013-6432",
    "CVE-2013-7027",
    "CVE-2013-7270",
    "CVE-2014-3645",
    "CVE-2014-3687",
    "CVE-2014-9710",
    "CVE-2016-2053",
    "CVE-2016-2062",
    "CVE-2016-3139",
    "CVE-2016-9806",
    "CVE-2017-10662",
    "CVE-2017-10810",
    "CVE-2017-17053",
    "CVE-2017-18208",
    "CVE-2017-7542",
    "CVE-2018-1108",
    "CVE-2018-17182",
    "CVE-2019-7222"
  );
  script_bugtraq_id(
    62048,
    64013,
    64135,
    64744,
    70746,
    70766,
    73308
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1526)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A double free vulnerability was found in netlink_dump,
    which could cause a denial of service or possibly other
    unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2016-9806)

  - Memory leak in drivers/media/video/videobuf-core.c in
    the videobuf subsystem in the Linux kernel 2.6.x
    through 4.x allows local users to cause a denial of
    service (memory consumption) by leveraging /dev/video
    access for a series of mmap calls that require new
    allocations, a different vulnerability than
    CVE-2007-6761. NOTE: as of 2016-06-18, this affects
    only 11 drivers that have not been updated to use
    videobuf2 instead of videobuf.(CVE-2010-5321)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2018-1108)

  - The KVM implementation in the Linux kernel through
    4.20.5 has an Information Leak.(CVE-2019-7222)

  - The adreno_perfcounter_query_group function in
    drivers/gpu/msm/adreno_perfcounter.c in the Adreno GPU
    driver for the Linux kernel 3.x, as used in Qualcomm
    Innovation Center (QuIC) Android contributions for MSM
    devices and other products, uses an incorrect integer
    data type, which allows attackers to cause a denial of
    service (integer overflow, heap-based buffer overflow,
    and incorrect memory allocation) or possibly have
    unspecified other impact via a crafted
    IOCTL_KGSL_PERFCOUNTER_QUERY ioctl call.(CVE-2016-2062)

  - drivers/hid/hid-ntrig.c in the Human Interface Device
    (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_NTRIG is enabled, allows physically
    proximate attackers to cause a denial of service (NULL
    pointer dereference and OOPS) via a crafted
    device.(CVE-2013-2896)

  - The wacom_probe function in
    drivers/input/tablet/wacom_sys.c in the Linux kernel
    before 3.17 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-3139)

  - An integer overflow vulnerability in
    ip6_find_1stfragopt() function was found. A local
    attacker that has privileges (of CAP_NET_RAW) to open
    raw socket can cause an infinite loop inside the
    ip6_find_1stfragopt() function.(CVE-2017-7542)

  - Memory leak in the virtio_gpu_object_create function in
    drivers/gpu/drm/virtio/virtgpu_object.c in the Linux
    kernel through 4.11.8 allows attackers to cause a
    denial of service (memory consumption) by triggering
    object-initialization failures.(CVE-2017-10810)

  - The ping_recvmsg function in net/ipv4/ping.c in the
    Linux kernel before 3.12.4 does not properly interact
    with read system calls on ping sockets, which allows
    local users to cause a denial of service (NULL pointer
    dereference and system crash) by leveraging unspecified
    privileges to execute a crafted
    application.(CVE-2013-6432)

  - The madvise_willneed function in the Linux kernel
    allows local users to cause a denial of service
    (infinite loop) by triggering use of MADVISE_WILLNEED
    for a DAX mapping.(CVE-2017-18208)

  - An issue was discovered in the Linux kernel through
    4.18.8. The vmacache_flush_all function in
    mm/vmacache.c mishandles sequence number overflows. An
    attacker can trigger a use-after-free (and possibly
    gain privileges) via certain thread creation, map,
    unmap, invalidation, and dereference
    operations.(CVE-2018-17182)

  - The ieee80211_radiotap_iterator_init function in
    net/wireless/radiotap.c in the Linux kernel before
    3.11.7 does not check whether a frame contains any data
    outside of the header, which might allow attackers to
    cause a denial of service (buffer over-read) via a
    crafted header.(CVE-2013-7027)

  - The Btrfs implementation in the Linux kernel before
    3.19 does not ensure that the visible xattr state is
    consistent with a requested replacement, which allows
    local users to bypass intended ACL settings and gain
    privileges via standard filesystem operations (1)
    during an xattr-replacement time window, related to a
    race condition, or (2) after an xattr-replacement
    attempt that fails because the data does not
    fit.(CVE-2014-9710)

  - A flaw was found in the way the Linux kernel's Stream
    Control Transmission Protocol (SCTP) implementation
    handled duplicate Address Configuration Change Chunks
    (ASCONF). A remote attacker could use either of these
    flaws to crash the system.(CVE-2014-3687)

  - A syntax vulnerability was discovered in the kernel's
    ASN1.1 DER decoder, which could lead to memory
    corruption or a complete local denial of service
    through x509 certificate DER files. A local system user
    could use a specially created key file to trigger
    BUG_ON() in the public_key_verify_signature() function
    (crypto/asymmetric_keys/public_key.c), to cause a
    kernel panic and crash the system.(CVE-2016-2053)

  - It was found that the Linux kernel's KVM subsystem did
    not handle the VM exits gracefully for the invept
    (Invalidate Translations Derived from EPT)
    instructions. On hosts with an Intel processor and
    invept VM exit support, an unprivileged guest user
    could use these instructions to crash the
    guest.(CVE-2014-3645)

  - The packet_recvmsg function in net/packet/af_packet.c
    in the Linux kernel before 3.12.4 updates a certain
    length value before ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7270)

  - The init_new_context function in
    arch/x86/include/asm/mmu_context.h in the Linux kernel,
    before 4.12.10, does not correctly handle errors from
    LDT table allocation when forking a new process. This
    could allow a local attacker to achieve a
    use-after-free or possibly have unspecified other
    impact by running a specially crafted
    program.(CVE-2017-17053)

  - It was found that the sanity_check_raw_super() function
    in 'fs/f2fs/super.c' file in the Linux kernel before
    version 4.12-rc1 does not validate the f2fs filesystem
    segment count. This allows an unprivileged local user
    to cause a system panic and DoS. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled
    out, although we believe it is
    unlikely.(CVE-2017-10662)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1526
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
