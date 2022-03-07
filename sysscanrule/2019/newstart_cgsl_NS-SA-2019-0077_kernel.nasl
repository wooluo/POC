#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0077. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127285);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2017-7294",
    "CVE-2017-15121",
    "CVE-2017-15126",
    "CVE-2019-6974",
    "CVE-2019-7221"
  );
  script_bugtraq_id(107127, 107294);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0077)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - A non-privileged user is able to mount a fuse filesystem
    on RHEL 6 or 7 and crash a system if an application
    punches a hole in a file that does not end aligned to a
    page boundary. (CVE-2017-15121)

  - A flaw was found in the Linux kernel's handling of fork
    failure when dealing with event messages in the
    userfaultfd code. Failure to fork correctly can create a
    fork event that will be removed from an already freed
    list of events. (CVE-2017-15126)

  - An out-of-bounds write vulnerability was found in the
    Linux kernel's vmw_surface_define_ioctl() function, in
    the 'drivers/gpu/drm/vmwgfx/vmwgfx_surface.c' file. Due
    to the nature of the flaw, privilege escalation cannot
    be fully ruled out, although we believe it is unlikely.
    (CVE-2017-7294)

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

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0077");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15126");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/29");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.331.gfd9c070.lite"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.13.328.gaf0e133"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
