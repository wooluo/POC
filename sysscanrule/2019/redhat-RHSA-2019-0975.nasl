#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0975. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124666);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/17  9:44:17");

  script_cve_id("CVE-2019-5736");
  script_xref(name:"RHSA", value:"2019:0975");

  script_name(english:"RHEL 8 : container-tools:rhel8 (RHSA-2019:0975)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for the container-tools:rhel8 module is now available for
Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The container-tools module contains tools for working with containers,
notably podman, buildah, skopeo, and runc.

Security Fix(es) :

* A flaw was found in the way runc handled system file descriptors
when running containers. A malicious container could use this flaw to
overwrite contents of the runc binary and consequently run arbitrary
commands on the container host system. (CVE-2019-5736)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* [stream rhel8] rebase container-selinux to 2.94 (BZ#1693675)

* [stream rhel8] unable to mount disk at `/var/lib/containers` via
`systemd` unit when `container-selinux` policy installed (BZ#1695669)

* [stream rhel8] don't allow a container to connect to random services
(BZ# 1695689)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5736"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-systemd-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-systemd-hook-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-systemd-hook-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-umount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-umount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-umount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/07");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:0975";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"buildah-1.5-3.gite94b4f9.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"buildah-1.5-3.gite94b4f9.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"buildah-debuginfo-1.5-3.gite94b4f9.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"buildah-debuginfo-1.5-3.gite94b4f9.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"buildah-debugsource-1.5-3.gite94b4f9.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"buildah-debugsource-1.5-3.gite94b4f9.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", reference:"container-selinux-2.94-1.git1e99f1d.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"containernetworking-plugins-0.7.4-3.git9ebe139.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"containernetworking-plugins-0.7.4-3.git9ebe139.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"containernetworking-plugins-debuginfo-0.7.4-3.git9ebe139.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"containernetworking-plugins-debuginfo-0.7.4-3.git9ebe139.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"containernetworking-plugins-debugsource-0.7.4-3.git9ebe139.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"containernetworking-plugins-debugsource-0.7.4-3.git9ebe139.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"containers-common-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"containers-common-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"fuse-overlayfs-0.3-2.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"fuse-overlayfs-0.3-2.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"fuse-overlayfs-debuginfo-0.3-2.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"fuse-overlayfs-debuginfo-0.3-2.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"fuse-overlayfs-debugsource-0.3-2.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"fuse-overlayfs-debugsource-0.3-2.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"oci-systemd-hook-debuginfo-0.1.15-2.git2d0b8a3.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"oci-systemd-hook-debuginfo-0.1.15-2.git2d0b8a3.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"oci-systemd-hook-debugsource-0.1.15-2.git2d0b8a3.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"oci-systemd-hook-debugsource-0.1.15-2.git2d0b8a3.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"oci-umount-2.3.4-2.git87f9237.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"oci-umount-2.3.4-2.git87f9237.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"oci-umount-debuginfo-2.3.4-2.git87f9237.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"oci-umount-debuginfo-2.3.4-2.git87f9237.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"oci-umount-debugsource-2.3.4-2.git87f9237.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"oci-umount-debugsource-2.3.4-2.git87f9237.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"podman-1.0.0-2.git921f98f.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"podman-1.0.0-2.git921f98f.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"podman-debuginfo-1.0.0-2.git921f98f.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"podman-debuginfo-1.0.0-2.git921f98f.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"podman-debugsource-1.0.0-2.git921f98f.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"podman-debugsource-1.0.0-2.git921f98f.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", reference:"podman-docker-1.0.0-2.git921f98f.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"runc-1.0.0-55.rc5.dev.git2abd837.module+el8.0.0+3049+59fd2bba")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"runc-1.0.0-55.rc5.dev.git2abd837.module+el8.0.0+3049+59fd2bba")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"runc-debuginfo-1.0.0-55.rc5.dev.git2abd837.module+el8.0.0+3049+59fd2bba")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"runc-debuginfo-1.0.0-55.rc5.dev.git2abd837.module+el8.0.0+3049+59fd2bba")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"runc-debugsource-1.0.0-55.rc5.dev.git2abd837.module+el8.0.0+3049+59fd2bba")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"runc-debugsource-1.0.0-55.rc5.dev.git2abd837.module+el8.0.0+3049+59fd2bba")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"skopeo-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"skopeo-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"skopeo-debuginfo-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"skopeo-debuginfo-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"skopeo-debugsource-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"skopeo-debugsource-0.1.32-3.git1715c90.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"slirp4netns-0.1-2.dev.gitc4e1bc5.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"slirp4netns-0.1-2.dev.gitc4e1bc5.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"slirp4netns-debuginfo-0.1-2.dev.gitc4e1bc5.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"slirp4netns-debuginfo-0.1-2.dev.gitc4e1bc5.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"slirp4netns-debugsource-0.1-2.dev.gitc4e1bc5.module+el8.0.0+2958+4e823551")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"slirp4netns-debugsource-0.1-2.dev.gitc4e1bc5.module+el8.0.0+2958+4e823551")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "buildah / buildah-debuginfo / buildah-debugsource / etc");
  }
}
