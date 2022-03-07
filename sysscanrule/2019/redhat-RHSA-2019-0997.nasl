#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0997. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124673);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/07 11:27:39");

  script_cve_id("CVE-2019-9636");
  script_xref(name:"RHSA", value:"2019:0997");

  script_name(english:"RHEL 8 : python3 (RHSA-2019:0997)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for python3 is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Python is an interpreted, interactive, object-oriented programming
language, which includes modules, classes, exceptions, very high level
dynamic data types and dynamic typing. Python supports interfaces to
many system calls and libraries, as well as to various windowing
systems.

This package provides the 'python3' executable: the reference
interpreter for the Python language, version 3. The majority of its
standard library is provided in the python3-libs package, which should
be installed automatically along with python3. The remaining parts of
the Python standard library are broken out into the python3-tkinter
and python3-test packages.

Security Fix(es) :

* python: Information Disclosure due to urlsplit improper NFKC
normalization (CVE-2019-9636)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://python-security.readthedocs.io/vuln/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-9636"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:platform-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:platform-python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:platform-python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/08");
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
  rhsa = "RHSA-2019:0997";
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
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"platform-python-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"platform-python-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"platform-python-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"platform-python-debug-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"platform-python-debug-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"platform-python-debug-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"platform-python-devel-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"platform-python-devel-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"platform-python-devel-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-debuginfo-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-debuginfo-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-debuginfo-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-debugsource-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-debugsource-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-debugsource-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-idle-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-idle-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-idle-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-libs-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libs-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libs-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-test-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-test-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-test-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-tkinter-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-tkinter-3.6.8-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-tkinter-3.6.8-2.el8_0")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "platform-python / platform-python-debug / platform-python-devel / etc");
  }
}
