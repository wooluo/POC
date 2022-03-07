#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:0975 and 
# Oracle Linux Security Advisory ELSA-2019-0975 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127569);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-5736");
  script_xref(name:"RHSA", value:"2019:0975");

  script_name(english:"Oracle Linux 8 : container-tools:rhel8 (ELSA-2019-0975)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:0975 :

An update for the container-tools:rhel8 module is now available for
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
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008959.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected container-tools:rhel8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oci-systemd-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oci-umount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"buildah-1.5-3.0.1.gite94b4f9.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"container-selinux-2.94-1.git1e99f1d.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"containernetworking-plugins-0.7.4-3.git9ebe139.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"containers-common-0.1.32-3.0.2.git1715c90.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"fuse-overlayfs-0.3-2.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"oci-umount-2.3.4-2.git87f9237.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"podman-1.0.0-2.0.1.git921f98f.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"podman-docker-1.0.0-2.0.1.git921f98f.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"runc-1.0.0-55.rc5.dev.git2abd837.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"skopeo-0.1.32-3.0.2.git1715c90.module+el8.0.0+5215+77f672ad")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"slirp4netns-0.1-2.dev.gitc4e1bc5.module+el8.0.0+5215+77f672ad")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "buildah / container-selinux / containernetworking-plugins / etc");
}
