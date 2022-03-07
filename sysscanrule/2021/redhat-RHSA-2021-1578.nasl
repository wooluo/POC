
##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1578. The text
# itself is copyright (C) Red Hat, Inc.
##


include('compat.inc');

if (description)
{
  script_id(149670);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id(
    "CVE-2019-18811",
    "CVE-2019-19523",
    "CVE-2019-19528",
    "CVE-2020-0431",
    "CVE-2020-11608",
    "CVE-2020-12114",
    "CVE-2020-12362",
    "CVE-2020-12464",
    "CVE-2020-14314",
    "CVE-2020-14356",
    "CVE-2020-15437",
    "CVE-2020-24394",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25643",
    "CVE-2020-25704",
    "CVE-2020-27786",
    "CVE-2020-27835",
    "CVE-2020-28974",
    "CVE-2020-35508",
    "CVE-2020-36322",
    "CVE-2021-0342"
  );
  script_xref(name:"RHSA", value:"2021:1578");

  script_name(english:"RHEL 8 : kernel (RHSA-2021:1578)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1578 advisory.

  - kernel: memory leak in sof_set_get_large_ctrl_data() function in sound/soc/sof/ipc.c (CVE-2019-18811)

  - kernel: use-after-free caused by a malicious USB device in the drivers/usb/misc/adutux.c driver
    (CVE-2019-19523)

  - kernel: use-after-free bug caused by a malicious USB device in the drivers/usb/misc/iowarrior.c driver
    (CVE-2019-19528)

  - kernel: possible out of bounds write in kbd_keycode of keyboard.c (CVE-2020-0431)

  - kernel: NULL pointer dereferences in ov511_mode_init_regs and ov518_mode_init_regs in
    drivers/media/usb/gspca/ov519.c (CVE-2020-11608)

  - kernel: DoS by corrupting mountpoint reference counter (CVE-2020-12114)

  - kernel: Integer overflow in Intel(R) Graphics Drivers (CVE-2020-12362)

  - kernel: Improper input validation in some Intel(R) Graphics Drivers (CVE-2020-12363)

  - kernel: Null pointer dereference in some Intel(R) Graphics Drivers (CVE-2020-12364)

  - kernel: use-after-free in usb_sg_cancel function in drivers/usb/core/message.c (CVE-2020-12464)

  - kernel: buffer uses out of index in ext3/4 filesystem (CVE-2020-14314)

  - kernel: Use After Free vulnerability in cgroup BPF component (CVE-2020-14356)

  - kernel: NULL pointer dereference in serial8250_isa_init_ports function in
    drivers/tty/serial/8250/8250_core.c (CVE-2020-15437)

  - kernel: umask not applied on filesystem without ACL support (CVE-2020-24394)

  - kernel: TOCTOU mismatch in the NFS client code (CVE-2020-25212)

  - kernel: incomplete permission checking for access to rbd devices (CVE-2020-25284)

  - kernel: race condition between hugetlb sysctl handlers in mm/hugetlb.c (CVE-2020-25285)

  - kernel: improper input validation in ppp_cp_parse_cr function leads to memory corruption and read overflow
    (CVE-2020-25643)

  - kernel: perf_event_parse_addr_filter memory (CVE-2020-25704)

  - kernel: use-after-free in kernel midi subsystem (CVE-2020-27786)

  - kernel: child process is able to access parent mm through hfi dev file handle (CVE-2020-27835)

  - kernel: slab-out-of-bounds read in fbcon (CVE-2020-28974)

  - kernel: fork: fix copy_process(CLONE_PARENT) race with the exiting ->real_parent (CVE-2020-35508)

  - kernel: fuse: fuse_do_getattr() calls make_bad_inode() in inappropriate situations (CVE-2020-36322)

  - kernel: use after free in tun_get_user of tun.c could lead to local escalation of privilege
    (CVE-2021-0342)

  - kernel: In pfkey_dump() dplen and splen can both be specified to access the xfrm_address_t structure out
    of bounds (CVE-2021-0605)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/190.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/284.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/362.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/367.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/400.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/459.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/665.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/732.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19523");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19528");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0431");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11608");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12114");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12362");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12363");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12364");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12464");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14314");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14356");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15437");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25212");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25284");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25285");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25704");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27786");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27835");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-35508");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36322");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-0342");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-0605");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1831726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1833445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1853922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1868453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1869141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1882591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1882594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1895961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1900933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1901161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1901709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1902724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1903126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1915799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1919889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1949560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1974823");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 125, 190, 284, 362, 367, 400, 416, 459, 476, 665, 732);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Red Hat' >!< release) audit(AUDIT_OS_NOT, 'Red Hat');
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

repositories = {
    'enterprise_linux_8_appstream': [
      'rhel-8-for-aarch64-appstream-debug-rpms',
      'rhel-8-for-aarch64-appstream-rpms',
      'rhel-8-for-aarch64-appstream-source-rpms',
      'rhel-8-for-s390x-appstream-debug-rpms',
      'rhel-8-for-s390x-appstream-rpms',
      'rhel-8-for-s390x-appstream-source-rpms',
      'rhel-8-for-x86_64-appstream-debug-rpms',
      'rhel-8-for-x86_64-appstream-rpms',
      'rhel-8-for-x86_64-appstream-source-rpms'
    ],
    'enterprise_linux_8_baseos': [
      'rhel-8-for-aarch64-baseos-debug-rpms',
      'rhel-8-for-aarch64-baseos-rpms',
      'rhel-8-for-aarch64-baseos-source-rpms',
      'rhel-8-for-s390x-baseos-debug-rpms',
      'rhel-8-for-s390x-baseos-rpms',
      'rhel-8-for-s390x-baseos-source-rpms',
      'rhel-8-for-x86_64-baseos-debug-rpms',
      'rhel-8-for-x86_64-baseos-rpms',
      'rhel-8-for-x86_64-baseos-source-rpms'
    ],
    'enterprise_linux_8_crb': [
      'codeready-builder-for-rhel-8-aarch64-debug-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms',
      'codeready-builder-for-rhel-8-aarch64-rpms',
      'codeready-builder-for-rhel-8-aarch64-source-rpms',
      'codeready-builder-for-rhel-8-s390x-debug-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms',
      'codeready-builder-for-rhel-8-s390x-rpms',
      'codeready-builder-for-rhel-8-s390x-source-rpms',
      'codeready-builder-for-rhel-8-x86_64-debug-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms',
      'codeready-builder-for-rhel-8-x86_64-rpms',
      'codeready-builder-for-rhel-8-x86_64-source-rpms'
    ],
    'enterprise_linux_8_highavailability': [
      'rhel-8-for-aarch64-highavailability-debug-rpms',
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms',
      'rhel-8-for-aarch64-highavailability-eus-rpms',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms',
      'rhel-8-for-aarch64-highavailability-rpms',
      'rhel-8-for-aarch64-highavailability-source-rpms',
      'rhel-8-for-s390x-highavailability-debug-rpms',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms',
      'rhel-8-for-s390x-highavailability-eus-rpms',
      'rhel-8-for-s390x-highavailability-eus-source-rpms',
      'rhel-8-for-s390x-highavailability-rpms',
      'rhel-8-for-s390x-highavailability-source-rpms',
      'rhel-8-for-x86_64-highavailability-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-eus-rpms',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms',
      'rhel-8-for-x86_64-highavailability-rpms',
      'rhel-8-for-x86_64-highavailability-source-rpms',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms'
    ],
    'enterprise_linux_8_nfv': [
      'rhel-8-for-x86_64-nfv-debug-rpms',
      'rhel-8-for-x86_64-nfv-rpms',
      'rhel-8-for-x86_64-nfv-source-rpms',
      'rhel-8-for-x86_64-nfv-tus-debug-rpms',
      'rhel-8-for-x86_64-nfv-tus-rpms',
      'rhel-8-for-x86_64-nfv-tus-source-rpms'
    ],
    'enterprise_linux_8_realtime': [
      'rhel-8-for-x86_64-rt-debug-rpms',
      'rhel-8-for-x86_64-rt-rpms',
      'rhel-8-for-x86_64-rt-source-rpms',
      'rhel-8-for-x86_64-rt-tus-debug-rpms',
      'rhel-8-for-x86_64-rt-tus-rpms',
      'rhel-8-for-x86_64-rt-tus-source-rpms'
    ],
    'enterprise_linux_8_resilientstorage': [
      'rhel-8-for-s390x-resilientstorage-debug-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms',
      'rhel-8-for-s390x-resilientstorage-rpms',
      'rhel-8-for-s390x-resilientstorage-source-rpms',
      'rhel-8-for-x86_64-resilientstorage-debug-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms',
      'rhel-8-for-x86_64-resilientstorage-rpms',
      'rhel-8-for-x86_64-resilientstorage-source-rpms'
    ],
    'enterprise_linux_8_sap': [
      'rhel-8-for-s390x-sap-netweaver-debug-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms',
      'rhel-8-for-s390x-sap-netweaver-rpms',
      'rhel-8-for-s390x-sap-netweaver-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-rpms',
      'rhel-8-for-x86_64-sap-netweaver-source-rpms'
    ],
    'enterprise_linux_8_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-rpms',
      'rhel-8-for-x86_64-sap-solutions-source-rpms'
    ],
    'enterprise_linux_8_supplementary': [
      'rhel-8-for-aarch64-supplementary-eus-rpms',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms',
      'rhel-8-for-aarch64-supplementary-rpms',
      'rhel-8-for-aarch64-supplementary-source-rpms',
      'rhel-8-for-s390x-supplementary-eus-rpms',
      'rhel-8-for-s390x-supplementary-eus-source-rpms',
      'rhel-8-for-s390x-supplementary-rpms',
      'rhel-8-for-s390x-supplementary-source-rpms',
      'rhel-8-for-x86_64-supplementary-eus-rpms',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms',
      'rhel-8-for-x86_64-supplementary-rpms',
      'rhel-8-for-x86_64-supplementary-source-rpms'
    ],
    'rhel_aus_8_4_appstream': [
      'rhel-8-for-x86_64-appstream-aus-debug-rpms',
      'rhel-8-for-x86_64-appstream-aus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-aus-rpms',
      'rhel-8-for-x86_64-appstream-aus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-aus-source-rpms',
      'rhel-8-for-x86_64-appstream-aus-source-rpms__8_DOT_4'
    ],
    'rhel_aus_8_4_baseos': [
      'rhel-8-for-x86_64-baseos-aus-debug-rpms',
      'rhel-8-for-x86_64-baseos-aus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-aus-rpms',
      'rhel-8-for-x86_64-baseos-aus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-aus-source-rpms',
      'rhel-8-for-x86_64-baseos-aus-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_appstream': [
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms',
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-e4s-rpms',
      'rhel-8-for-x86_64-appstream-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_baseos': [
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms',
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-e4s-rpms',
      'rhel-8-for-x86_64-baseos-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_highavailability': [
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_sap': [
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_appstream': [
      'rhel-8-for-aarch64-appstream-eus-debug-rpms',
      'rhel-8-for-aarch64-appstream-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-aarch64-appstream-eus-rpms',
      'rhel-8-for-aarch64-appstream-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-appstream-eus-source-rpms',
      'rhel-8-for-aarch64-appstream-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-appstream-eus-debug-rpms',
      'rhel-8-for-s390x-appstream-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-appstream-eus-rpms',
      'rhel-8-for-s390x-appstream-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-appstream-eus-source-rpms',
      'rhel-8-for-s390x-appstream-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-aus-debug-rpms',
      'rhel-8-for-x86_64-appstream-aus-rpms',
      'rhel-8-for-x86_64-appstream-aus-source-rpms',
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms',
      'rhel-8-for-x86_64-appstream-e4s-rpms',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms',
      'rhel-8-for-x86_64-appstream-eus-debug-rpms',
      'rhel-8-for-x86_64-appstream-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-eus-rpms',
      'rhel-8-for-x86_64-appstream-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-eus-source-rpms',
      'rhel-8-for-x86_64-appstream-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-tus-debug-rpms',
      'rhel-8-for-x86_64-appstream-tus-rpms',
      'rhel-8-for-x86_64-appstream-tus-source-rpms'
    ],
    'rhel_eus_8_4_baseos': [
      'rhel-8-for-aarch64-baseos-eus-debug-rpms',
      'rhel-8-for-aarch64-baseos-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-aarch64-baseos-eus-rpms',
      'rhel-8-for-aarch64-baseos-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-baseos-eus-source-rpms',
      'rhel-8-for-aarch64-baseos-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-baseos-eus-debug-rpms',
      'rhel-8-for-s390x-baseos-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-baseos-eus-rpms',
      'rhel-8-for-s390x-baseos-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-baseos-eus-source-rpms',
      'rhel-8-for-s390x-baseos-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-aus-debug-rpms',
      'rhel-8-for-x86_64-baseos-aus-rpms',
      'rhel-8-for-x86_64-baseos-aus-source-rpms',
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms',
      'rhel-8-for-x86_64-baseos-e4s-rpms',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms',
      'rhel-8-for-x86_64-baseos-eus-debug-rpms',
      'rhel-8-for-x86_64-baseos-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-eus-rpms',
      'rhel-8-for-x86_64-baseos-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-eus-source-rpms',
      'rhel-8-for-x86_64-baseos-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-tus-debug-rpms',
      'rhel-8-for-x86_64-baseos-tus-rpms',
      'rhel-8-for-x86_64-baseos-tus-source-rpms'
    ],
    'rhel_eus_8_4_crb': [
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-s390x-eus-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_highavailability': [
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms',
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-aarch64-highavailability-eus-rpms',
      'rhel-8-for-aarch64-highavailability-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-highavailability-eus-rpms',
      'rhel-8-for-s390x-highavailability-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-highavailability-eus-source-rpms',
      'rhel-8-for-s390x-highavailability-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-eus-rpms',
      'rhel-8-for-x86_64-highavailability-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms'
    ],
    'rhel_eus_8_4_resilientstorage': [
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-resilientstorage-eus-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_sap': [
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_supplementary': [
      'rhel-8-for-aarch64-supplementary-eus-rpms',
      'rhel-8-for-aarch64-supplementary-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-supplementary-eus-rpms',
      'rhel-8-for-s390x-supplementary-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-supplementary-eus-source-rpms',
      'rhel-8-for-s390x-supplementary-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-supplementary-eus-rpms',
      'rhel-8-for-x86_64-supplementary-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms__8_DOT_4'
    ],
    'rhel_extras_nfv_8': [
      'rhel-8-for-x86_64-nfv-debug-rpms',
      'rhel-8-for-x86_64-nfv-rpms',
      'rhel-8-for-x86_64-nfv-source-rpms',
      'rhel-8-for-x86_64-nfv-tus-debug-rpms',
      'rhel-8-for-x86_64-nfv-tus-rpms',
      'rhel-8-for-x86_64-nfv-tus-source-rpms'
    ],
    'rhel_extras_rt_8': [
      'rhel-8-for-x86_64-nfv-debug-rpms',
      'rhel-8-for-x86_64-nfv-rpms',
      'rhel-8-for-x86_64-nfv-source-rpms',
      'rhel-8-for-x86_64-rt-debug-rpms',
      'rhel-8-for-x86_64-rt-rpms',
      'rhel-8-for-x86_64-rt-source-rpms',
      'rhel-8-for-x86_64-rt-tus-debug-rpms',
      'rhel-8-for-x86_64-rt-tus-rpms',
      'rhel-8-for-x86_64-rt-tus-source-rpms'
    ],
    'rhel_tus_8_4_appstream': [
      'rhel-8-for-x86_64-appstream-tus-debug-rpms',
      'rhel-8-for-x86_64-appstream-tus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-tus-rpms',
      'rhel-8-for-x86_64-appstream-tus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-tus-source-rpms',
      'rhel-8-for-x86_64-appstream-tus-source-rpms__8_DOT_4'
    ],
    'rhel_tus_8_4_baseos': [
      'rhel-8-for-x86_64-baseos-tus-debug-rpms',
      'rhel-8-for-x86_64-baseos-tus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-tus-rpms',
      'rhel-8-for-x86_64-baseos-tus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-tus-source-rpms',
      'rhel-8-for-x86_64-baseos-tus-source-rpms__8_DOT_4'
    ],
    'rhel_tus_8_4_highavailability': [
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms__8_DOT_4'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
enterprise_linux_flag = rhel_repo_sets_has_enterprise_linux(repo_sets:repo_sets);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2021-0342', 'CVE-2021-0605');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:1578');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'bpftool-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'bpftool-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'bpftool-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-abi-stablelists-4.18.0-305.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-core-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-core-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-core-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-cross-headers-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-cross-headers-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-cross-headers-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-core-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-core-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-core-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-extra-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-extra-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-extra-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-headers-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-headers-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-headers-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-extra-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-extra-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-extra-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-core-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-devel-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-modules-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'perf-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'perf-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'perf-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'python3-perf-4.18.0-305.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'python3-perf-4.18.0-305.el8', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'python3-perf-4.18.0-305.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  repo_list = NULL;
  if (!empty_or_null(package_array['repo_list'])) repo_list = package_array['repo_list'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
  if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    repocheck = rhel_decide_repo_check(repo_list:repo_list, repo_sets:repo_sets);
    if (repocheck && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  if (empty_or_null(repo_sets)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
