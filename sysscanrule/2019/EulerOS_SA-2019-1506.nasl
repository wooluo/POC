#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124829);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-2891",
    "CVE-2013-6368",
    "CVE-2014-2523",
    "CVE-2014-9322",
    "CVE-2015-0274",
    "CVE-2015-4700",
    "CVE-2015-8944",
    "CVE-2016-0823",
    "CVE-2016-1575",
    "CVE-2016-5728",
    "CVE-2016-6516",
    "CVE-2016-6787",
    "CVE-2017-1000380",
    "CVE-2017-12153",
    "CVE-2017-14156",
    "CVE-2017-5576",
    "CVE-2017-6353",
    "CVE-2017-6951",
    "CVE-2018-14613",
    "CVE-2019-8980"
  );
  script_bugtraq_id(
    62047,
    64291,
    66279,
    71685,
    73156,
    75356
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1506)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The pagemap_open function in fs/proc/task_mmu.c in the
    Linux kernel before 3.19.3, as used in Android 6.0.1
    before 2016-03-01, allows local users to obtain
    sensitive physical-address information by reading a
    pagemap file, aka Android internal bug
    25739721.(CVE-2016-0823)

  - drivers/hid/hid-steelseries.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_STEELSERIES is enabled, allows
    physically proximate attackers to cause a denial of
    service (heap-based out-of-bounds write) via a crafted
    device.(CVE-2013-2891)

  - The overlayfs implementation in the Linux kernel
    through 4.5.2 does not properly maintain POSIX ACL
    xattr data, which allows local users to gain privileges
    by leveraging a group-writable setgid
    directory.(CVE-2016-1575)

  - Integer overflow in the vc4_get_bcl function in
    drivers/gpu/drm/vc4/vc4_gem.c in the VideoCore DRM
    driver in the Linux kernel before 4.9.7 allows local
    users to cause a denial of service or possibly have
    unspecified other impact via a crafted size value in a
    VC4_SUBMIT_CL ioctl call.(CVE-2017-5576)

  - The KVM subsystem in the Linux kernel through 3.12.5
    allows local users to gain privileges or cause a denial
    of service (system crash) via a VAPIC synchronization
    operation involving a page-end address.(CVE-2013-6368)

  - It was found that the code in net/sctp/socket.c in the
    Linux kernel through 4.10.1 does not properly restrict
    association peel-off operations during certain wait
    states, which allows local users to cause a denial of
    service (invalid unlock and double free) via a
    multithreaded application. This vulnerability was
    introduced by CVE-2017-5986 fix (commit
    2dcab5984841).(CVE-2017-6353)

  - net/netfilter/nf_conntrack_proto_dccp.c in the Linux
    kernel through 3.13.6 uses a DCCP header pointer
    incorrectly, which allows remote attackers to cause a
    denial of service (system crash) or possibly execute
    arbitrary code via a DCCP packet that triggers a call
    to the (1) dccp_new, (2) dccp_packet, or (3) dccp_error
    function.(CVE-2014-2523)

  - Race condition vulnerability was found in
    drivers/misc/mic/vop/vop_vringh.c in the MIC VOP driver
    in the Linux kernel before 4.6.1. MIC VOP driver does
    two successive reads from user space to read a variable
    length data structure. Local user can obtain sensitive
    information from kernel memory or can cause DoS by
    corrupting kernel memory if the data structure changes
    between the two reads.(CVE-2016-5728)

  - An issue was discovered in the btrfs filesystem code in
    the Linux kernel. An invalid pointer dereference in
    io_ctl_map_page() when mounting and operating a crafted
    btrfs image is due to a lack of block group item
    validation in check_leaf_item() in
    fs/btrfs/tree-checker.c function. This could lead to a
    system crash and a denial of service.(CVE-2018-14613)

  - A flaw was found in the way the Linux kernel handled GS
    segment register base switching when recovering from a
    #SS (stack segment) fault on an erroneous return to
    user space. A local, unprivileged user could use this
    flaw to escalate their privileges on the
    system.(CVE-2014-9322)

  - The keyring_search_aux function in
    security/keys/keyring.c in the Linux kernel allows
    local users to cause a denial of service via a
    request_key system call for the 'dead' key
    type.(CVE-2017-6951)

  - A flaw was found in the way the Linux kernel's XFS file
    system handled replacing of remote attributes under
    certain conditions. A local user with access to XFS
    file system mount could potentially use this flaw to
    escalate their privileges on the system.(CVE-2015-0274)

  - A memory leak in the kernel_read_file function in
    fs/exec.c in the Linux kernel through 4.20.11 allows
    attackers to cause a denial of service (memory
    consumption) by triggering vfs_read
    failures.(CVE-2019-8980)

  - A flaw was found in the kernel's implementation of the
    Berkeley Packet Filter (BPF). A local attacker could
    craft BPF code to crash the system by creating a
    situation in which the JIT compiler would fail to
    correctly optimize the JIT image on the last pass. This
    would lead to the CPU executing instructions that were
    not part of the JIT code.(CVE-2015-4700)

  - A security flaw was discovered in
    nl80211_set_rekey_data() function in the Linux kernel
    since v3.1-rc1 through v4.13. This function does not
    check whether the required attributes are present in a
    netlink request. This request can be issued by a user
    with CAP_NET_ADMIN privilege and may result in NULL
    dereference and a system crash.(CVE-2017-12153)

  - The atyfb_ioctl function in
    drivers/video/fbdev/aty/atyfb_base.c in the Linux
    kernel through 4.12.10 does not initialize a certain
    data structure, which allows local users to obtain
    sensitive information from kernel stack memory by
    reading locations associated with padding
    bytes.(CVE-2017-14156)

  - kernel/events/core.c in the performance subsystem in
    the Linux kernel before 4.0 mismanages locks during
    certain migrations, which allows local users to gain
    privileges via a crafted application, aka Android
    internal bug 31095224.(CVE-2016-6787)

  - The ioresources_init function in kernel/resource.c in
    the Linux kernel through 4.7, as used in Android before
    2016-08-05 on Nexus 6 and 7 (2013) devices, uses weak
    permissions for /proc/iomem, which allows local users
    to obtain sensitive information by reading this file,
    aka Android internal bug 28814213 and Qualcomm internal
    bug CR786116. NOTE: the permissions may be intentional
    in most non-Android contexts.(CVE-2015-8944)

  - Race condition in the ioctl_file_dedupe_range function
    in fs/ioctl.c in the Linux kernel through 4.7 allows
    local users to cause a denial of service (heap-based
    buffer overflow) or possibly gain privileges by
    changing a certain count value, aka a 'double fetch'
    vulnerability.(CVE-2016-6516)

  - It was found that the timer functionality in the Linux
    kernel ALSA subsystem is prone to a race condition
    between read and ioctl system call handlers, resulting
    in an uninitialized memory disclosure to user space. A
    local user could use this flaw to read information
    belonging to other users.(CVE-2017-1000380)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1506
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

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
