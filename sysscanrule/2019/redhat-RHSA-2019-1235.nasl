#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1235. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125201);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/19 13:26:28");

  script_cve_id("CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_xref(name:"RHSA", value:"2019:1235");

  script_name(english:"RHEL 7 : ruby (RHSA-2019:1235)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ruby is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to perform system
management tasks.

Security Fix(es) :

* rubygems: Installing a malicious gem may lead to arbitrary code
execution (CVE-2019-8324)

* rubygems: Escape sequence injection vulnerability in gem owner
(CVE-2019-8322)

* rubygems: Escape sequence injection vulnerability in API response
handling (CVE-2019-8323)

* rubygems: Escape sequence injection vulnerability in errors
(CVE-2019-8325)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-8322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-8323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-8324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-8325"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1235";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ruby-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ruby-debuginfo-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ruby-devel-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-devel-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ruby-doc-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ruby-irb-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ruby-libs-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ruby-tcltk-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-tcltk-2.0.0.648-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"rubygem-bigdecimal-1.2.0-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-bigdecimal-1.2.0-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"rubygem-io-console-0.4.2-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-io-console-0.4.2-35.el7_6")) flag++;

  if (rpm_exists(rpm:"rubygem-json-1.7", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"s390x", reference:"rubygem-json-1.7.7-35.el7_6")) flag++;

  if (rpm_exists(rpm:"rubygem-json-1.7", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-json-1.7.7-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"rubygem-minitest-4.3.2-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"rubygem-psych-2.0.0-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-psych-2.0.0-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"rubygem-rake-0.9.6-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"rubygem-rdoc-4.0.0-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"rubygems-2.0.14.1-35.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"rubygems-devel-2.0.14.1-35.el7_6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-doc / ruby-irb / etc");
  }
}
