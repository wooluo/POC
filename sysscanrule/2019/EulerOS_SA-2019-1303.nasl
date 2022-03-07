#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124430);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2016-10741",
    "CVE-2018-10879",
    "CVE-2018-10883",
    "CVE-2018-16862",
    "CVE-2018-17972",
    "CVE-2018-18559",
    "CVE-2018-19824",
    "CVE-2019-5489"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2019-1303)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A new software page cache side channel attack scenario
    was discovered in operating systems that implement the
    very common 'page cache' caching mechanism. A malicious
    user/process could use 'in memory' page-cache knowledge
    to infer access timings to shared memory and gain
    knowledge which can be used to reduce effectiveness of
    cryptographic strength by monitoring algorithmic
    behavior, infer access patterns of memory to determine
    code paths taken, and exfiltrate data to a blinded
    attacker through page-granularity access times as a
    side-channel.(CVE-2019-5489)

  - It was found that the Linux kernel can hit a BUG_ON()
    statement in the __xfs_get_blocks() in the
    fs/xfs/xfs_aops.c because of a race condition between
    direct and memory-mapped I/O associated with a hole in
    a file that is handled with BUG_ON() instead of an I/O
    failure. This allows a local unprivileged attacker to
    cause a system crash and a denial of
    service.(CVE-2016-10741)

  - An issue was discovered in the proc_pid_stack function
    in fs/proc/base.c in the Linux kernel. An attacker with
    a local account can trick the stack unwinder code to
    leak stack contents to userspace. The fix allows only
    root to inspect the kernel stack of an arbitrary
    task.(CVE-2018-17972)

  - A security flaw was found in the Linux kernel in a way
    that the cleancache subsystem clears an inode after the
    final file truncation (removal). The new file created
    with the same inode may contain leftover pages from
    cleancache and the old file data instead of the new
    one.(CVE-2018-16862)

  - A use-after-free flaw can occur in the Linux kernel due
    to a race condition between packet_do_bind() and
    packet_notifier() functions called for an AF_PACKET
    socket. An unprivileged, local user could use this flaw
    to induce kernel memory corruption on the system,
    leading to an unresponsive system or to a crash. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out.(CVE-2018-18559)

  - A flaw was found In the Linux kernel, through version
    4.19.6, where a local user could exploit a
    use-after-free in the ALSA driver by supplying a
    malicious USB Sound device (with zero interfaces) that
    is mishandled in usb_audio_probe in sound/usb/card.c.
    An attacker could corrupt memory and possibly escalate
    privileges if the attacker is able to have physical
    access to the system.(CVE-2018-19824)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause a use-after-free in
    ext4_xattr_set_entry function and a denial of service
    or unspecified other impact may occur by renaming a
    file in a crafted ext4 filesystem
    image.(CVE-2018-10879)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound write in
    jbd2_journal_dirty_metadata(), a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image.(CVE-2018-10883)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1303
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h179",
        "kernel-debuginfo-3.10.0-514.44.5.10.h179",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h179",
        "kernel-devel-3.10.0-514.44.5.10.h179",
        "kernel-headers-3.10.0-514.44.5.10.h179",
        "kernel-tools-3.10.0-514.44.5.10.h179",
        "kernel-tools-libs-3.10.0-514.44.5.10.h179",
        "perf-3.10.0-514.44.5.10.h179",
        "python-perf-3.10.0-514.44.5.10.h179"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
