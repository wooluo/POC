#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1517. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126026);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/19 13:26:27");

  script_cve_id("CVE-2019-3827");
  script_xref(name:"RHSA", value:"2019:1517");

  script_name(english:"RHEL 8 : gvfs (RHSA-2019:1517)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gvfs is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GVFS is the GNOME Desktop Virtual File System layer that allows users
to easily access local and remote data using File Transfer Protocol
(FTP), Secure Shell File Transfer Protocol (SFTP), Web Distributed
Authoring and Versioning (WebDAV), Common Internet File System (CIFS),
Server Message Block (SMB), and other protocols. GVFS integrates with
the GNOME I/O (GIO) abstraction layer.

Security Fix(es) :

* gvfs: Incorrect authorization in admin backend allows privileged
users to read and modify arbitrary files without prompting for
password (CVE-2019-3827)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3827"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-archive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-goa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-gphoto2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-mtp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-smb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");
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
  rhsa = "RHSA-2019:1517";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afc-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-afc-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afc-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afp-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-afp-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-afp-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afp-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-archive-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-archive-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-archive-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-archive-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-client-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-client-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-client-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-client-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-client-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-client-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-debugsource-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-debugsource-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-debugsource-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-devel-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-devel-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-devel-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-fuse-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-fuse-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-fuse-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-fuse-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-fuse-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-goa-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-goa-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-goa-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-goa-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-gphoto2-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-gphoto2-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-gphoto2-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-gphoto2-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-gphoto2-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-mtp-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-mtp-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-mtp-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-mtp-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-mtp-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-smb-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-smb-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-smb-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-smb-debuginfo-1.36.2-2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-smb-debuginfo-1.36.2-2.el8_0.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs / gvfs-afc / gvfs-afc-debuginfo / gvfs-afp / etc");
  }
}
