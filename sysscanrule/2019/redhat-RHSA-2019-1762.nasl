#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1762. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126679);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-10161", "CVE-2019-10166", "CVE-2019-10167", "CVE-2019-10168");
  script_xref(name:"RHSA", value:"2019:1762");

  script_name(english:"RHEL 64 / 8 : virt:8.0.0 (RHSA-2019:1762)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for the virt:8.0.0 module is now available for Red Hat
Enterprise Linux 8 Advanced Virtualization.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Advanced Virtualization module provides the user-space component
for running virtual machines that use KVM in environments managed by
Red Hat products.

Security Fix(es) :

* libvirt: arbitrary file read/exec via virDomainSaveImageGetXMLDesc
API (CVE-2019-10161)

* libvirt: virDomainManagedSaveDefineXML API exposed to readonly
clients (CVE-2019-10166)

* libvirt: arbitrary command execution via
virConnectGetDomainCapabilities API (CVE-2019-10167)

* libvirt: arbitrary command execution via
virConnectBaselineHypervisorCPU and virConnectCompareHypervisorCPU
APIs (CVE-2019-10168)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-10161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-10166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-10167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-10168"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SLOF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-benchmarking-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-gobject-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-tools-c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libiscsi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libssh2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libssh2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-admin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-disk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-iscsi-direct-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-logical-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-mpath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-scsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-dbus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lua-guestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-basic-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-example-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-gzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-gzip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-python-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-vddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-vddk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-xz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nbdkit-plugin-xz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcf-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Guestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Virt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Virt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:supermin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:supermin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-dib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-p2v-maker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-v2v-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(64|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 64.x / 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1762";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"hivex-debugsource-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"hivex-devel-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", reference:"libguestfs-bash-completion-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-debugsource-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-devel-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-gfs2-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-gobject-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-gobject-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-gobject-devel-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", reference:"libguestfs-inspect-icons-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-java-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-java-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-java-devel-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", reference:"libguestfs-javadoc-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", reference:"libguestfs-man-pages-ja-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", reference:"libguestfs-man-pages-uk-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-rescue-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-rsync-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", reference:"libguestfs-tools-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-tools-c-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-tools-c-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-winsupport-8.0-2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libguestfs-xfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libiscsi-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libiscsi-debuginfo-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libiscsi-debugsource-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libiscsi-devel-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libiscsi-utils-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libiscsi-utils-debuginfo-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libssh2-1.8.0-7.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libssh2-debuginfo-1.8.0-7.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libssh2-debugsource-1.8.0-7.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-admin-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-admin-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-bash-completion-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-client-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-client-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-config-network-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-config-nwfilter-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-interface-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-interface-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-network-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-network-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-nodedev-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-nodedev-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-nwfilter-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-nwfilter-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-qemu-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-qemu-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-secret-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-secret-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-core-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-core-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-disk-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-disk-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-gluster-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-gluster-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-iscsi-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-iscsi-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-iscsi-direct-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-iscsi-direct-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-logical-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-logical-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-mpath-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-mpath-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-rbd-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-rbd-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-scsi-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-driver-storage-scsi-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-daemon-kvm-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-dbus-1.3.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-dbus-debuginfo-1.3.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-dbus-debugsource-1.3.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-debugsource-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-devel-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-docs-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-libs-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-libs-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-lock-sanlock-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-lock-sanlock-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-nss-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-nss-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"libvirt-python-debugsource-5.0.0-3.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"lua-guestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"lua-guestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", reference:"nbdkit-bash-completion-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-basic-plugins-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-basic-plugins-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-debugsource-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-devel-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-example-plugins-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-example-plugins-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-plugin-gzip-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-plugin-gzip-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-plugin-python-common-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-plugin-python3-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-plugin-python3-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-plugin-xz-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"nbdkit-plugin-xz-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"netcf-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"netcf-debuginfo-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"netcf-debugsource-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"netcf-devel-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"netcf-libs-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"netcf-libs-debuginfo-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"perl-Sys-Guestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"perl-Sys-Guestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"perl-Sys-Virt-5.0.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"perl-Sys-Virt-debuginfo-5.0.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"perl-Sys-Virt-debugsource-5.0.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"perl-hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"perl-hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"python3-hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"python3-hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"python3-libguestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"python3-libguestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"python3-libvirt-5.0.0-3.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"python3-libvirt-debuginfo-5.0.0-3.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-guest-agent-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-guest-agent-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-img-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-img-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-curl-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-curl-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-iscsi-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-iscsi-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-rbd-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-rbd-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-ssh-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-block-ssh-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-common-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-common-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-core-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-core-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"qemu-kvm-debugsource-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"ruby-hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"ruby-hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"ruby-libguestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"ruby-libguestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"supermin-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"supermin-debuginfo-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"supermin-debugsource-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"supermin-devel-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"virt-dib-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL64", cpu:"s390x", reference:"virt-dib-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;

  if (rpm_check(release:"RHEL8", reference:"SLOF-20180702-3.git9b7ab2f.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"hivex-debugsource-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"hivex-devel-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"libguestfs-bash-completion-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-benchmarking-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-benchmarking-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-debugsource-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-devel-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-gfs2-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-gobject-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-gobject-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-gobject-devel-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"libguestfs-inspect-icons-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-java-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-java-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-java-devel-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"libguestfs-javadoc-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"libguestfs-man-pages-ja-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"libguestfs-man-pages-uk-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-rescue-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-rsync-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"libguestfs-tools-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-tools-c-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-tools-c-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-winsupport-8.0-2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libguestfs-xfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libiscsi-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libiscsi-debuginfo-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libiscsi-debugsource-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libiscsi-devel-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libiscsi-utils-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libiscsi-utils-debuginfo-1.18.0-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libssh2-1.8.0-7.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libssh2-debuginfo-1.8.0-7.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libssh2-debugsource-1.8.0-7.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-admin-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-admin-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-bash-completion-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-client-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-client-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-config-network-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-network-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-network-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-direct-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-direct-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-daemon-kvm-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-dbus-1.3.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-dbus-debuginfo-1.3.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-dbus-debugsource-1.3.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-debugsource-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-devel-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-docs-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-libs-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-libs-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-lock-sanlock-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-lock-sanlock-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-nss-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-nss-debuginfo-5.0.0-7.2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libvirt-python-debugsource-5.0.0-3.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"lua-guestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"lua-guestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"nbdkit-bash-completion-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-basic-plugins-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-basic-plugins-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-debugsource-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-devel-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-example-plugins-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-example-plugins-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-gzip-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-gzip-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-python-common-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-python3-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-python3-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-vddk-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-vddk-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-xz-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nbdkit-plugin-xz-debuginfo-1.4.2-4.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"netcf-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"netcf-debuginfo-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"netcf-debugsource-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"netcf-devel-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"netcf-libs-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"netcf-libs-debuginfo-0.2.8-10.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-Sys-Guestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-Sys-Virt-5.0.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-Sys-Virt-debuginfo-5.0.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-Sys-Virt-debugsource-5.0.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libguestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libguestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libvirt-5.0.0-3.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libvirt-debuginfo-5.0.0-3.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-guest-agent-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-guest-agent-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-img-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-img-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-curl-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-curl-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-gluster-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-gluster-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-iscsi-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-iscsi-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-rbd-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-rbd-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-ssh-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-block-ssh-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-common-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-common-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-core-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-core-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-debuginfo-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qemu-kvm-debugsource-3.1.0-20.module+el8.0.0.z+3438+2851622e.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-hivex-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-hivex-debuginfo-1.3.15-6.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-libguestfs-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-libguestfs-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"seabios-1.12.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"seabios-bin-1.12.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"seavgabios-bin-1.12.0-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sgabios-0.20170427git-2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", reference:"sgabios-bin-0.20170427git-2.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"supermin-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"supermin-debuginfo-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"supermin-debugsource-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"supermin-devel-5.1.19-8.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"virt-dib-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"virt-dib-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"virt-p2v-maker-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"virt-v2v-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"virt-v2v-debuginfo-1.40.2-1.module+el8.0.0.z+3438+2851622e")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SLOF / hivex / hivex-debuginfo / hivex-debugsource / hivex-devel / etc");
  }
}
