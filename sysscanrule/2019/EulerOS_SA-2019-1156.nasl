#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123630);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2018-10902",
    "CVE-2018-1118",
    "CVE-2018-16862",
    "CVE-2018-18710",
    "CVE-2018-20169",
    "CVE-2018-5848",
    "CVE-2019-5489",
    "CVE-2019-9213"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1156)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in the Linux kernel through
    4.19. An information leak in cdrom_ioctl_select_disc in
    drivers/cdrom/cdrom.c could be used by local attackers
    to read kernel memory because a cast from unsigned long
    to int interferes with bounds checking. This is similar
    to CVE-2018-10940 and CVE-2018-16658.(CVE-2018-18710)

  - A flaw was found in mmap in the Linux kernel allowing
    the process to map a null page. This allows attackers
    to abuse this mechanism to turn null pointer
    dereferences into workable exploits.(CVE-2019-9213)

  - The Linux kernel does not properly initialize memory in
    messages passed between virtual guests and the host
    operating system in the vhost/vhost.c:vhost_new_msg()
    function. This can allow local privileged users to read
    some kernel memory contents when reading from the
    /dev/vhost-net device file.(CVE-2018-1118)

  - It was found that the raw midi kernel driver does not
    protect against concurrent access which leads to a
    double realloc (double free) in
    snd_rawmidi_input_params() and
    snd_rawmidi_output_status() which are part of
    snd_rawmidi_ioctl() handler in rawmidi.c file. A
    malicious local attacker could possibly use this for
    privilege escalation.(CVE-2018-10902)

  - A flaw was discovered in the Linux kernel's USB
    subsystem in the __usb_get_extra_descriptor() function
    in the drivers/usb/core/usb.c which mishandles a size
    check during the reading of an extra descriptor data.
    By using a specially crafted USB device which sends a
    forged extra descriptor, an unprivileged user with
    physical access to the system can potentially cause a
    privilege escalation or trigger a system crash or lock
    up and thus to cause a denial of service
    (DoS).(CVE-2018-20169)

  - In the function wmi_set_ie() in the Linux kernel the
    length validation code does not handle unsigned integer
    overflow properly. As a result, a large value of the
    'ie_len' argument can cause a buffer overflow and thus
    a memory corruption leading to a system crash or other
    or unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-5848)

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

  - A security flaw was found in the Linux kernel in a way
    that the cleancache subsystem clears an inode after the
    final file truncation (removal). The new file created
    with the same inode may contain leftover pages from
    cleancache and the old file data instead of the new
    one.(CVE-2018-16862)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1156
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/02");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "kernel-debuginfo-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "kernel-debuginfo-common-x86_64-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "perf-3.10.0-862.14.0.1.h105.eulerosv2r7",
        "python-perf-3.10.0-862.14.0.1.h105.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
