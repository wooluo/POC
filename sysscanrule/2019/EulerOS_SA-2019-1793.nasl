#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127564);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id(
    "CVE-2019-11487",
    "CVE-2019-11833",
    "CVE-2019-11884",
    "CVE-2019-7222"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2019-1793)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The Linux kernel before 5.1-rc5 allows page->_refcount
    reference count overflow, with resultant use-after-free
    issues, if about 140 GiB of RAM exists. This is related
    to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h,
    kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It
    can occur with FUSE requests.(CVE-2019-11487)

  - A flaw was found in the Linux kernel's implementation
    of ext4 extent management. The kernel doesn't correctly
    initialize memory regions in the extent tree block
    which may be exported to a local user to obtain
    sensitive information by reading empty/uninitialized
    data from the filesystem.(CVE-2019-11833)

  - A flaw was found in the Linux kernel's implementation
    of the Bluetooth Human Interface Device Protocol
    (HIDP). A local attacker with access permissions to the
    Bluetooth device can issue an IOCTL which will trigger
    the do_hidp_sock_ioctl function in
    net/bluetooth/hidp/sock.c.c. This function can leak
    potentially sensitive information from the kernel stack
    memory via a HIDPCONNADD command because a name field
    may not be correctly NULL terminated.(CVE-2019-11884)

  - An information leakage issue was found in the way Linux
    kernel's KVM hypervisor handled page fault exceptions
    while emulating instructions like VMXON, VMCLEAR,
    VMPTRLD, and VMWRITE with memory address as an operand.
    It occurs if the operand is a mmio address, as the
    returned exception object holds uninitialized stack
    memory contents. A guest user/process could use this
    flaw to leak host's stack memory contents to a
    guest.(CVE-2019-7222)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1793
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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

pkgs = ["kernel-3.10.0-327.62.59.83.h167",
        "kernel-debug-3.10.0-327.62.59.83.h167",
        "kernel-debug-devel-3.10.0-327.62.59.83.h167",
        "kernel-debuginfo-3.10.0-327.62.59.83.h167",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h167",
        "kernel-devel-3.10.0-327.62.59.83.h167",
        "kernel-headers-3.10.0-327.62.59.83.h167",
        "kernel-tools-3.10.0-327.62.59.83.h167",
        "kernel-tools-libs-3.10.0-327.62.59.83.h167",
        "perf-3.10.0-327.62.59.83.h167",
        "python-perf-3.10.0-327.62.59.83.h167"];

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
