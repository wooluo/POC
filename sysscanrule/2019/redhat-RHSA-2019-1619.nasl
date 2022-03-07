#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1619. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126302);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/02 12:46:54");

  script_cve_id("CVE-2019-12735");
  script_xref(name:"RHSA", value:"2019:1619");

  script_name(english:"RHEL 7 / 8 : vim (RHSA-2019:1619)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for vim is now available for Red Hat Enterprise Linux 7 and
Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Vim (Vi IMproved) is an updated and improved version of the vi editor.

Security Fix(es) :

* vim/neovim: ':source!' command allows arbitrary command execution
via modelines (CVE-2019-12735)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-12735"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-X11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-enhanced-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/27");
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
if (! ereg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x / 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1619";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-X11-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-X11-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-common-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-common-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-debuginfo-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-debuginfo-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-enhanced-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-enhanced-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-filesystem-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-filesystem-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-minimal-7.4.160-6.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-minimal-7.4.160-6.el7_6")) flag++;


  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-X11-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-X11-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-X11-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-X11-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-common-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-common-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-common-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-common-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-debugsource-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-debugsource-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-enhanced-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-enhanced-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-enhanced-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-enhanced-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", reference:"vim-filesystem-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-minimal-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-minimal-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"vim-minimal-debuginfo-8.0.1763-11.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"vim-minimal-debuginfo-8.0.1763-11.el8_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-X11 / vim-X11-debuginfo / vim-common / vim-common-debuginfo / etc");
  }
}
