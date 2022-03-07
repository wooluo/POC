#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125587);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2012-2744",
    "CVE-2012-3400",
    "CVE-2013-2164",
    "CVE-2013-2206",
    "CVE-2013-6282",
    "CVE-2017-0786",
    "CVE-2018-20836",
    "CVE-2018-7191",
    "CVE-2019-11190",
    "CVE-2019-11486",
    "CVE-2019-11487",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-11811"
  );
  script_bugtraq_id(
    54279,
    54367,
    60375,
    60715,
    63734
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2019-1635)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An issue was discovered in the Linux kernel before
    4.20. There is a race condition in smp_task_timedout()
    and smp_task_done() in
    drivers/scsi/libsas/sas_expander.c, leading to a
    use-after-free.(CVE-2018-20836)

  - The Linux kernel before 4.8 allows local users to
    bypass ASLR on setuid programs (such as /bin/su)
    because install_exec_creds() is called too late in
    load_elf_binary() in fs/binfmt_elf.c, and thus the
    ptrace_may_access() check has a race condition when
    reading /proc/pid/stat.(CVE-2019-11190)

  - The Siemens R3964 line discipline driver in
    drivers/tty/n_r3964.c in the Linux kernel before 5.0.8
    has multiple race conditions.(CVE-2019-11486)

  - The Linux kernel before 5.1-rc5 allows page->_refcount
    reference count overflow, with resultant use-after-free
    issues, if about 140 GiB of RAM exists. This is related
    to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h,
    kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It
    can occur with FUSE requests.(CVE-2019-11487)

  - The coredump implementation in the Linux kernel before
    5.0.10 does not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs,
    which allows local users to obtain sensitive
    information, cause a denial of service, or possibly
    have unspecified other impact by triggering a race
    condition with mmget_not_zero or get_task_mm calls.
    This is related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and
    drivers/infiniband/core/uverbs_main.c.(CVE-2019-11599)

  - An issue was discovered in the Linux kernel before
    5.0.7. A NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in
    megasas_alloc_cmds() in
    drivers/scsi/megaraid/megaraid_sas_base.c. This causes
    a Denial of Service, related to a
    use-after-free.(CVE-2019-11810)

  - In the tun subsystem in the Linux kernel before
    4.13.14, dev_get_valid_name is not called before
    register_netdevice. This allows local users to cause a
    denial of service (NULL pointer dereference and panic)
    via an ioctl(TUNSETIFF) call with a dev name containing
    a / character. This is similar to
    CVE-2013-4343.(CVE-2018-7191)

  - net/ipv6/netfilter/nf_conntrack_reasm.c in the Linux
    kernel before 2.6.34, when the nf_conntrack_ipv6 module
    is enabled, allows remote attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via certain types of fragmented IPv6
    packets.(CVE-2012-2744)

  - Heap-based buffer overflow in the udf_load_logicalvol
    function in fs/udf/super.c in the Linux kernel before
    3.4.5 allows remote attackers to cause a denial of
    service (system crash) or possibly have unspecified
    other impact via a crafted UDF
    filesystem.(CVE-2012-3400)

  - The mmc_ioctl_cdrom_read_data function in
    drivers/cdrom/cdrom.c in the Linux kernel through 3.10
    allows local users to obtain sensitive information from
    kernel memory via a read operation on a malfunctioning
    CD-ROM drive.(CVE-2013-2164)

  - The (1) get_user and (2) put_user API functions in the
    Linux kernel before 3.5.5 on the v6k and v7 ARM
    platforms do not validate certain addresses, which
    allows attackers to read or modify the contents of
    arbitrary kernel memory locations via a crafted
    application, as exploited in the wild against Android
    devices in October and November 2013.(CVE-2013-6282)

  - The sctp_sf_do_5_2_4_dupcook function in
    net/sctp/sm_statefuns.c in the SCTP implementation in
    the Linux kernel before 3.8.5 does not properly handle
    associations during the processing of a duplicate
    COOKIE ECHO chunk, which allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via crafted SCTP traffic.(CVE-2013-2206)

  - A elevation of privilege vulnerability in the Broadcom
    wi-fi driver. Product: Android. Versions: Android
    kernel. Android ID: A-37351060. References:
    B-V2017060101.(CVE-2017-0786)

  - An issue was discovered in the Linux kernel before
    5.0.4. There is a use-after-free upon attempted read
    access to /proc/ioports after the ipmi_si module is
    removed, related to drivers/char/ipmi/ipmi_si_intf.c,
    drivers/char/ipmi/ipmi_si_mem_io.c, and
    drivers/char/ipmi/ipmi_si_port_io.c.(CVE-2019-11811)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1635
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android get_user/put_user Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
