#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1175 and 
# Oracle Linux Security Advisory ELSA-2019-1175 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127584);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-20815", "CVE-2019-11091", "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3863");
  script_xref(name:"RHSA", value:"2019:1175");

  script_name(english:"Oracle Linux 8 : virt:rhel (ELSA-2019-1175) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:1175 :

An update for the virt:rhel module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kernel-based Virtual Machine (KVM) offers a full virtualization
solution for Linux on numerous hardware platforms. The virt:rhel
module contains packages which provide user-space components used to
run virtual machines using KVM. The packages also provide APIs for
managing and interacting with the virtualized systems.

Security Fix(es) :

* A flaw was found in the implementation of the 'fill buffer', a
mechanism used by modern CPUs when a cache-miss is made on L1 CPU
cache. If an attacker can generate a load operation that would create
a page fault, the execution will continue speculatively with incorrect
data from the fill buffer while the data is fetched from higher level
caches. This response time can be measured to infer data in the fill
buffer. (CVE-2018-12130)

* Modern Intel microprocessors implement hardware-level
micro-optimizations to improve the performance of writing data back to
CPU caches. The write operation is split into STA (STore Address) and
STD (STore Data) sub-operations. These sub-operations allow the
processor to hand-off address generation logic into these
sub-operations for optimized writes. Both of these sub-operations
write to a shared distributed processor structure called the
'processor store buffer'. As a result, an unprivileged attacker could
use this flaw to read private data resident within the CPU's processor
store buffer. (CVE-2018-12126)

* Microprocessors use a 'load port' subcomponent to perform load
operations from memory or IO. During a load operation, the load port
receives data from the memory or IO subsystem and then provides the
data to the CPU registers and operations in the CPU's pipelines.
Stale load operations results are stored in the 'load port' table
until overwritten by newer operations. Certain load-port operations
triggered by an attacker can be used to reveal data about previous
stale requests leaking data back to the attacker via a timing
side-channel. (CVE-2018-12127)

* Uncacheable memory on some microprocessors utilizing speculative
execution may allow an authenticated user to potentially enable
information disclosure via a side channel with local access.
(CVE-2019-11091)

* QEMU: device_tree: heap buffer overflow while loading device tree
blob (CVE-2018-20815)

* libssh2: Integer overflow in transport read resulting in out of
bounds write (CVE-2019-3855)

* libssh2: Integer overflow in keyboard interactive handling resulting
in out of bounds write (CVE-2019-3856)

* libssh2: Integer overflow in SSH packet processing channel resulting
in out of bounds write (CVE-2019-3857)

* libssh2: Integer overflow in user authenticate keyboard interactive
allows out-of-bounds writes (CVE-2019-3863)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008975.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virt:rhel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-plugin-gzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-plugin-python-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-plugin-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-plugin-vddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-plugin-xz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-p2v-maker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"hivex-1.3.15-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"hivex-devel-1.3.15-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-bash-completion-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-benchmarking-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-devel-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-gfs2-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-gobject-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-gobject-devel-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-inspect-icons-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-java-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-java-devel-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-javadoc-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-man-pages-ja-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-man-pages-uk-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-rescue-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-rsync-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-tools-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-tools-c-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-winsupport-8.0-2.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libguestfs-xfs-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libiscsi-1.18.0-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libiscsi-devel-1.18.0-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libiscsi-utils-1.18.0-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libssh2-1.8.0-7.module+el8.0.0+5219+3c0c6858.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-admin-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-bash-completion-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-client-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-config-network-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-network-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-kvm-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-dbus-1.2.0-2.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-devel-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-docs-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-libs-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-lock-sanlock-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-nss-4.5.0-23.1.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"lua-guestfs-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-bash-completion-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-basic-plugins-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-devel-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-example-plugins-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-plugin-gzip-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-plugin-python-common-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-plugin-python3-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-plugin-vddk-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nbdkit-plugin-xz-1.4.2-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"netcf-0.2.8-10.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"netcf-devel-0.2.8-10.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"netcf-libs-0.2.8-10.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perl-Sys-Virt-4.5.0-4.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perl-hivex-1.3.15-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-hivex-1.3.15-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-libguestfs-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-libvirt-4.5.0-1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-guest-agent-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-img-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-block-curl-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-block-gluster-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-block-iscsi-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-block-rbd-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-block-ssh-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-common-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"qemu-kvm-core-2.12.0-64.module+el8.0.0+5219+3c0c6858.2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"ruby-hivex-1.3.15-6.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"ruby-libguestfs-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"seabios-1.11.1-3.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"seabios-bin-1.11.1-3.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"seavgabios-bin-1.11.1-3.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"sgabios-0.20170427git-2.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"sgabios-bin-0.20170427git-2.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"supermin-5.1.19-8.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"supermin-devel-5.1.19-8.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"virt-dib-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"virt-p2v-maker-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"virt-v2v-1.38.4-10.0.1.module+el8.0.0+5219+3c0c6858")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hivex / hivex-devel / libguestfs / libguestfs-bash-completion / etc");
}
