#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2512. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127992);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-0203");
  script_xref(name:"RHSA", value:"2019:2512");

  script_name(english:"RHEL 8 : subversion:1.10 (RHSA-2019:2512)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for the subversion:1.10 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.

Security Fix(es) :

* subversion: NULL pointer dereference in svnserve leading to an
unauthenticated remote DoS (CVE-2019-0203)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0203"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libserf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libserf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libserf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_dav_svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:utf8proc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:utf8proc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:utf8proc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
  rhsa = "RHSA-2019:2512";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libserf-1.3.9-9.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libserf-1.3.9-9.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libserf-debuginfo-1.3.9-9.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libserf-debuginfo-1.3.9-9.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libserf-debugsource-1.3.9-9.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libserf-debugsource-1.3.9-9.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_dav_svn-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_dav_svn-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_dav_svn-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_dav_svn-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-debugsource-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-debugsource-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-devel-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-devel-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-devel-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-devel-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-gnome-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-gnome-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-gnome-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-gnome-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", reference:"subversion-javahl-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-libs-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-libs-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-libs-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-libs-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-perl-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-perl-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-perl-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-perl-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-tools-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-tools-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"subversion-tools-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"subversion-tools-debuginfo-1.10.2-2.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"utf8proc-2.1.1-5.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"utf8proc-2.1.1-5.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"utf8proc-debuginfo-2.1.1-5.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"utf8proc-debuginfo-2.1.1-5.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"utf8proc-debugsource-2.1.1-5.module+el8.0.0+3900+919b6753")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"utf8proc-debugsource-2.1.1-5.module+el8.0.0+3900+919b6753")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libserf / libserf-debuginfo / libserf-debugsource / mod_dav_svn / etc");
  }
}
