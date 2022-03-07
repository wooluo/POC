#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124988);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-2929",
    "CVE-2013-6382",
    "CVE-2013-7271",
    "CVE-2013-7348",
    "CVE-2014-1738",
    "CVE-2014-8172",
    "CVE-2015-4167",
    "CVE-2015-4177",
    "CVE-2015-4692",
    "CVE-2016-1583",
    "CVE-2016-2064",
    "CVE-2016-3140",
    "CVE-2016-5829",
    "CVE-2016-7912",
    "CVE-2016-9793",
    "CVE-2017-16645",
    "CVE-2017-7487",
    "CVE-2017-9986",
    "CVE-2018-5333",
    "CVE-2019-9857"
  );
  script_bugtraq_id(
    63889,
    64111,
    64746,
    66544,
    67302,
    72994,
    74963,
    75142
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1535)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The ims_pcu_get_cdc_union_desc function in
    drivers/input/misc/ims-pcu.c in the Linux kernel,
    through 4.13.11, allows local users to cause a denial
    of service (ims_pcu_parse_cdc_data out-of-bounds read
    and system crash) or possibly have unspecified other
    impact via a crafted USB device.(CVE-2017-16645)

  - It was found that due to excessive files_lock locking,
    a soft lockup could be triggered in the Linux kernel
    when performing asynchronous I/O operations. A local,
    unprivileged user could use this flaw to crash the
    system.(CVE-2014-8172)

  - A flaw was discovered in the kernel's collect_mounts
    function. If the kernel's audit subsystem called
    collect_mounts to audit an unmounted path, it could
    panic the system. With this flaw, an unprivileged user
    could call umount(MNT_DETACH) to launch a
    denial-of-service attack.(CVE-2015-4177)

  - A flaw was found in the way the Linux kernel's floppy
    driver handled user space provided data in certain
    error code paths while processing FDRAWCMD IOCTL
    commands. A local user with write access to /dev/fdX
    could use this flaw to free (using the kfree()
    function) arbitrary kernel memory. (CVE-2014-1737,
    Important) was found that the Linux kernel's floppy
    driver leaked internal kernel memory addresses to user
    space during the processing of the FDRAWCMD IOCTL
    command. A local user with write access to /dev/fdX
    could use this flaw to obtain information about the
    kernel heap arrangement. (CVE-2014-1738, Low)Note: A
    local user with write access to /dev/fdX could use
    these two flaws (CVE-2014-1737 in combination with
    CVE-2014-1738) to escalate their privileges on the
    system.(CVE-2014-1738)

  - A reference counter leak in Linux kernel in
    ipxitf_ioctl function was found which results in a use
    after free vulnerability that's triggerable from
    unprivileged userspace when IPX interface is
    configured.(CVE-2017-7487)

  - The x25_recvmsg function in net/x25/af_x25.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7271)

  - An inode data validation error was found in Linux
    kernels built with UDF file system (CONFIG_UDF_FS)
    support. An attacker able to mount a
    corrupted/malicious UDF file system image could cause
    the kernel to crash.(CVE-2015-4167)

  - Double free vulnerability in the ioctx_alloc function
    in fs/aio.c in the Linux kernel before 3.12.4 allows
    local users to cause a denial of service (system crash)
    or possibly have unspecified other impact via vectors
    involving an error condition in the aio_setup_ring
    function.(CVE-2013-7348)

  - A flaw was found in the Linux kernel's implementation
    of setsockopt for the SO_{SND|RCV}BUFFORCE setsockopt()
    system call. Users with non-namespace CAP_NET_ADMIN are
    able to trigger this call and create a situation in
    which the sockets sendbuff data size could be negative.
    This could adversely affect memory allocations and
    create situations where the system could crash or cause
    memory corruption.(CVE-2016-9793)

  - Use-after-free vulnerability in the
    ffs_user_copy_worker function in
    drivers/usb/gadget/function/f_fs.c in the Linux kernel
    before 4.5.3 allows local users to gain privileges by
    accessing an I/O data structure after a certain
    callback call. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.(CVE-2016-7912)

  - A flaw was found in the way the get_dumpable() function
    return value was interpreted in the ptrace subsystem of
    the Linux kernel. When 'fs.suid_dumpable' was set to 2,
    a local, unprivileged local user could use this flaw to
    bypass intended ptrace restrictions and obtain
    potentially sensitive information.(CVE-2013-2929)

  - A DoS flaw was found for a Linux kernel built for the
    x86 architecture which had the KVM virtualization
    support(CONFIG_KVM) enabled. The kernel would be
    vulnerable to a NULL pointer dereference flaw in Linux
    kernel's kvm_apic_has_events() function while doing an
    ioctl. An unprivileged user able to access the
    '/dev/kvm' device could use this flaw to crash the
    system kernel.(CVE-2015-4692)

  - The intr function in sound/oss/msnd_pinnacle.c in the
    Linux kernel through 4.11.7 allows local users to cause
    a denial of service (over-boundary access) or possibly
    have unspecified other impact by changing the value of
    a message queue head pointer between two kernel reads
    of that value, aka a 'double fetch'
    vulnerability.(CVE-2017-9986)

  - sound/soc/msm/qdsp6v2/msm-audio-effects-q6-v2.c in the
    MSM QDSP6 audio driver for the Linux kernel 3.x, as
    used in Qualcomm Innovation Center (QuIC) Android
    contributions for MSM devices and other products,
    allows attackers to cause a denial of service (buffer
    over-read) or possibly have unspecified other impact
    via a crafted application that makes an ioctl call
    specifying many commands.(CVE-2016-2064)

  - The digi_port_init function in
    drivers/usb/serial/digi_acceleport.c in the Linux
    kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a crafted endpoints
    value in a USB device descriptor.(CVE-2016-3140)

  - In the Linux kernel through 4.14.13, the
    rds_cmsg_atomic function in net/rds/rdma.c mishandles
    cases where page pinning fails or an invalid address is
    supplied, leading to an rds_atomic_free_op NULL pointer
    dereference.(CVE-2018-5333)

  - Multiple buffer underflows in the XFS implementation in
    the Linux kernel through 3.12.1 allow local users to
    cause a denial of service (memory corruption) or
    possibly have unspecified other impact by leveraging
    the CAP_SYS_ADMIN capability for a (1)
    XFS_IOC_ATTRLIST_BY_HANDLE or (2)
    XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted
    length value, related to the xfs_attrlist_by_handle
    function in fs/xfs/xfs_ioctl.c and the
    xfs_compat_attrlist_by_handle function in
    fs/xfs/xfs_ioctl32.c.(CVE-2013-6382)

  - In the Linux kernel through 5.0.2, the function
    inotify_update_existing_watch() in
    fs/notify/inotify/inotify_user.c neglects to call
    fsnotify_put_mark() with IN_MASK_CREATE after
    fsnotify_find_mark(), which will cause a memory leak
    (aka refcount leak). Finally, this will cause a denial
    of service.(CVE-2019-9857)

  - It was found that stacking a file system over procfs in
    the Linux kernel could lead to a kernel stack overflow
    due to deep nesting, as demonstrated by mounting
    ecryptfs over procfs and creating a recursion by
    mapping /proc/environ. An unprivileged, local user
    could potentially use this flaw to escalate their
    privileges on the system.(CVE-2016-1583)

  - A heap-based buffer overflow vulnerability was found in
    the Linux kernel's hiddev driver. This flaw could allow
    a local attacker to corrupt kernel memory, possible
    privilege escalation or crashing the
    system.(CVE-2016-5829)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1535
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

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
