#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0085. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127301);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-6974",
    "CVE-2019-7221",
    "CVE-2019-11091"
  );
  script_bugtraq_id(107127, 107294);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0085)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel packages installed that are affected by
multiple vulnerabilities:

  - A use-after-free vulnerability was found in the way the
    Linux kernel's KVM hypervisor emulates a preemption
    timer for L2 guests when nested (=1) virtualization is
    enabled. This high resolution timer(hrtimer) runs when a
    L2 guest is active. After VM exit, the sync_vmcs12()
    timer object is stopped. The use-after-free occurs if
    the timer object is freed before calling sync_vmcs12()
    routine. A guest user/process could use this flaw to
    crash the host kernel resulting in a denial of service
    or, potentially, gain privileged access to a system.
    (CVE-2019-7221)

  - A use-after-free vulnerability was found in the way the
    Linux kernel's KVM hypervisor implements its device
    control API. While creating a device via
    kvm_ioctl_create_device(), the device holds a reference
    to a VM object, later this reference is transferred to
    the caller's file descriptor table. If such file
    descriptor was to be closed, reference count to the VM
    object could become zero, potentially leading to a use-
    after-free issue. A user/process could use this flaw to
    crash the guest VM resulting in a denial of service
    issue or, potentially, gain privileged access to a
    system. (CVE-2019-6974)

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

  - A flaw was found in the implementation of the fill
    buffer, a mechanism used by modern CPUs when a cache-
    miss is made on L1 CPU cache. If an attacker can
    generate a load operation that would create a page
    fault, the execution will continue speculatively with
    incorrect data from the fill buffer while the data is
    fetched from higher level caches. This response time can
    be measured to infer data in the fill buffer.
    (CVE-2018-12130)

  - Uncacheable memory on some microprocessors utilizing
    speculative execution may allow an authenticated user to
    potentially enable information disclosure via a side
    channel with local access. (CVE-2019-11091)

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

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0085");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6974");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/15");
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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "bpftool-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-abi-whitelists-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-core-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-debug-core-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-debug-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-debug-devel-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-debug-modules-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-devel-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-doc-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-headers-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-modules-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-tools-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-tools-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-tools-libs-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "kernel-tools-libs-devel-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "perf-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "perf-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "python-perf-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite",
    "python-perf-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.69.g9598392.lite"
  ],
  "CGSL MAIN 5.05": [
    "bpftool-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-abi-whitelists-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-debug-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-debug-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-debug-devel-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-debuginfo-common-x86_64-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-devel-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-doc-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-headers-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-tools-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-tools-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-tools-libs-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "kernel-tools-libs-devel-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "perf-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "perf-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "python-perf-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8",
    "python-perf-debuginfo-3.10.0-957.12.2.el7.cgslv5_5.2.66.gc3d61d8"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
