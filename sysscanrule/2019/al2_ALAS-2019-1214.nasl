#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1214.
#

include("compat.inc");

if (description)
{
  script_id(125598);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-10142", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-3882", "CVE-2019-5489", "CVE-2019-9500");
  script_xref(name:"ALAS", value:"2019-1214");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2019-1214)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the Linux kernel's freescale hypervisor manager
implementation. A parameter passed via to an ioctl was incorrectly
validated and used in size calculations for the page size calculation.
An attacker can use this flaw to crash the system or corrupt memory
or, possibly, create other adverse security affects.(CVE-2019-10142)

A new software page cache side channel attack scenario was discovered
in operating systems that implement the very common 'page cache'
caching mechanism. A malicious user/process could use 'in memory'
page-cache knowledge to infer access timings to shared memory and gain
knowledge which can be used to reduce effectiveness of cryptographic
strength by monitoring algorithmic behavior, infer access patterns of
memory to determine code paths taken, and exfiltrate data to a blinded
attacker through page-granularity access times as a side-channel.
(CVE-2019-5489)

The do_hidp_sock_ioctl function in net/bluetooth/hidp/sock.c in the
Linux kernel before 5.0.15 allows a local user to obtain potentially
sensitive information from kernel stack memory via a HIDPCONNADD
command, because a name field may not end with a '\0'
character.(CVE-2019-11884)

A flaw was found in the Linux kernel's vfio interface implementation
that permits violation of the user's locked memory limit. If a device
is bound to a vfio driver, such as vfio-pci, and the local attacker is
administratively granted ownership of the device, it may cause a
system memory exhaustion and thus a denial of service
(DoS).(CVE-2019-3882)

If the Wake-up on Wireless LAN functionality is configured in the
brcmfmac driver, which only works with Broadcom FullMAC chipsets, a
malicious event frame can be constructed to trigger a heap buffer
overflow in the brcmf_wowl_nd_results() function. This vulnerability
can be exploited by compromised chipsets to compromise the host, or
when used in combination with another brcmfmac driver flaw
(CVE-2019-9503), can be used remotely. This can result in a remote
denial of service (DoS). Due to the nature of the flaw, a remote
privilege escalation cannot be fully ruled out.(CVE-2019-9500)

A flaw was found in the Linux kernel's implementation of ext4 extent
management. The kernel doesn't correctly initialize memory regions in
the extent tree block which may be exported to a local user to obtain
sensitive information by reading empty/uninitialized data from the
filesystem. (CVE-2019-11833)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1214.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-devel-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"kernel-headers-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-devel-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-debuginfo-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-4.14.121-109.96.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-debuginfo-4.14.121-109.96.amzn2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
