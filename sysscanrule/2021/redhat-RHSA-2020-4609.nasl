##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4609. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142382);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id(
    "CVE-2019-9455",
    "CVE-2019-9458",
    "CVE-2019-15917",
    "CVE-2019-15925",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-18808",
    "CVE-2019-18809",
    "CVE-2019-19046",
    "CVE-2019-19056",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19068",
    "CVE-2019-19072",
    "CVE-2019-19319",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19524",
    "CVE-2019-19533",
    "CVE-2019-19537",
    "CVE-2019-19543",
    "CVE-2019-19767",
    "CVE-2019-19770",
    "CVE-2019-20054",
    "CVE-2019-20636",
    "CVE-2020-0305",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10774",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-11668",
    "CVE-2020-12655",
    "CVE-2020-12659",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14381",
    "CVE-2020-25641"
  );
  script_xref(name:"RHSA", value:"2020:4609");

  script_name(english:"RHEL 8 : kernel-rt (RHSA-2020:4609)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4609 advisory.

  - kernel: use-after-free in drivers/bluetooth/hci_ldisc.c (CVE-2019-15917)

  - kernel: out-of-bounds access in function hclge_tm_schd_mode_vnet_base_cfg (CVE-2019-15925)

  - kernel: null-pointer dereference in drivers/net/fjes/fjes_main.c (CVE-2019-16231)

  - kernel: null pointer dereference in drivers/scsi/qla2xxx/qla_os.c (CVE-2019-16233)

  - kernel: memory leak in ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c (CVE-2019-18808)

  - kernel: memory leak in  af9005_identify_state() function in drivers/media/usb/dvb-usb/af9005.c
    (CVE-2019-18809)

  - kernel: Denial Of Service in the __ipmi_bmc_register() function in drivers/char/ipmi/ipmi_msghandler.c
    (CVE-2019-19046)

  - kernel: A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c allows to cause DoS (CVE-2019-19056)

  - kernel: memory leak in the crypto_report() function in crypto/crypto_user_base.c allows for DoS
    (CVE-2019-19062)

  - kernel: Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c
    allow for a DoS (CVE-2019-19063)

  - kernel: A memory leak in the rtl8xxxu_submit_int_urb() function in
    drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c allows for a DoS (CVE-2019-19068)

  - kernel: A memory leak in the predicate_parse() function in kernel/trace/trace_events_filter.c allows for a
    DoS (CVE-2019-19072)

  - kernel: out-of-bounds write in ext4_xattr_set_entry in fs/ext4/xattr.c (CVE-2019-19319)

  - Kernel: kvm: OOB memory write via kvm_dev_ioctl_get_cpuid (CVE-2019-19332)

  - kernel: mounting a crafted ext4 filesystem image, performing some operations, and unmounting can lead to a
    use-after-free in ext4_put_super in fs/ext4/super.c (CVE-2019-19447)

  - kernel: a malicious USB device in the drivers/input/ff-memless.c leads to use-after-free (CVE-2019-19524)

  - kernel: information leak bug caused  by a malicious USB device in the drivers/media/usb/ttusb-
    dec/ttusb_dec.c (CVE-2019-19533)

  - kernel: race condition caused by a malicious USB device in the USB character device driver layer
    (CVE-2019-19537)

  - kernel: use-after-free in serial_ir_init_module() in drivers/media/rc/serial_ir.c (CVE-2019-19543)

  - kernel: use-after-free in __ext4_expand_extra_isize and ext4_xattr_set_entry related to fs/ext4/inode.c
    and fs/ext4/super.c (CVE-2019-19767)

  - kernel: use-after-free in debugfs_remove in fs/debugfs/inode.c (CVE-2019-19770)

  - kernel: Null pointer dereference in drop_sysctl_table() in fs/proc/proc_sysctl.c (CVE-2019-20054)

  - kernel: out-of-bounds write via crafted keycode table (CVE-2019-20636)

  - kernel: kernel pointer leak due to WARN_ON statement in video driver leads to local information disclosure
    (CVE-2019-9455)

  - kernel: use after free due to race condition in the video driver leads to local privilege escalation
    (CVE-2019-9458)

  - kernel: possible use-after-free due to a race condition in cdev_get of char_dev.c (CVE-2020-0305)

  - kernel: uninitialized kernel data leak in userspace coredumps (CVE-2020-10732)

  - kernel: SELinux netlink permission check bypass (CVE-2020-10751)

  - kernel: possibility of memory disclosure when reading the file /proc/sys/kernel/rh_features
    (CVE-2020-10774)

  - kernel: vhost-net: stack overflow in get_raw_socket while checking sk_family field (CVE-2020-10942)

  - kernel: out-of-bounds write in mpol_parse_str function in mm/mempolicy.c (CVE-2020-11565)

  - kernel: mishandles invalid descriptors in drivers/media/usb/gspca/xirlink_cit.c (CVE-2020-11668)

  - kernel: sync of excessive duration via an XFS v5 image with crafted metadata (CVE-2020-12655)

  - kernel: xdp_umem_reg in net/xdp/xdp_umem.c has an out-of-bounds write which could result in crash and data
    coruption (CVE-2020-12659)

  - kernel: sg_write function lacks an sg_remove_request call in a certain failure case (CVE-2020-12770)

  - kernel: possible to send arbitrary signals to a privileged (suidroot) parent process (CVE-2020-12826)

  - kernel: referencing inode of removed superblock in get_futex_key() causes UAF (CVE-2020-14381)

  - kernel: soft-lockups in iov_iter_copy_from_user_atomic() could result in DoS (CVE-2020-25641)

  - kernel: out-of-bounds read in in vc_do_resize function in drivers/tty/vt/vt.c (CVE-2020-8647)

  - kernel: use-after-free in n_tty_receive_buf_common function in drivers/tty/n_tty.c (CVE-2020-8648)

  - kernel: invalid read location in vgacon_invert_region function in drivers/video/console/vgacon.c
    (CVE-2020-8649)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/94.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/349.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/362.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/400.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/401.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/772.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/835.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/909.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9455");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9458");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15917");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15925");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16231");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16233");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18809");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19056");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19062");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19063");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19068");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19072");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19319");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19332");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19447");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19524");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19533");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19543");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19767");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20054");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8648");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8649");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10732");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10751");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10774");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10942");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11565");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11668");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12655");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12826");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14381");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25641");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1759052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1779594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1784130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1817718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1819377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1819399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1822077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1831399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1832543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1832876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1834845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1839634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1846964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1860065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1874311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1881424");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12659");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 119, 200, 349, 362, 400, 401, 416, 476, 772, 787, 805, 835, 909);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  cve_list = make_list('CVE-2019-9455', 'CVE-2019-9458', 'CVE-2019-15917', 'CVE-2019-15925', 'CVE-2019-16231', 'CVE-2019-16233', 'CVE-2019-18808', 'CVE-2019-18809', 'CVE-2019-19046', 'CVE-2019-19056', 'CVE-2019-19062', 'CVE-2019-19063', 'CVE-2019-19068', 'CVE-2019-19072', 'CVE-2019-19319', 'CVE-2019-19332', 'CVE-2019-19447', 'CVE-2019-19524', 'CVE-2019-19533', 'CVE-2019-19537', 'CVE-2019-19543', 'CVE-2019-19767', 'CVE-2019-19770', 'CVE-2019-20054', 'CVE-2019-20636', 'CVE-2020-0305', 'CVE-2020-8647', 'CVE-2020-8648', 'CVE-2020-8649', 'CVE-2020-10732', 'CVE-2020-10751', 'CVE-2020-10774', 'CVE-2020-10942', 'CVE-2020-11565', 'CVE-2020-11668', 'CVE-2020-12655', 'CVE-2020-12659', 'CVE-2020-12770', 'CVE-2020-12826', 'CVE-2020-14381', 'CVE-2020-25641');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:4609');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'kernel-rt-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-core-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-core-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-devel-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-kvm-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-modules-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-devel-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-kvm-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-modules-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-modules-extra-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
