#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:0997 and 
# Oracle Linux Security Advisory ELSA-2019-0997 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127576);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-9636");
  script_xref(name:"RHSA", value:"2019:0997");

  script_name(english:"Oracle Linux 8 : python3 (ELSA-2019-0997)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:0997 :

An update for python3 is now available for Red Hat Enterprise Linux 8.

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
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008967.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:platform-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:platform-python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:platform-python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/08");
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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"platform-python-3.6.8-2.0.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"platform-python-debug-3.6.8-2.0.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"platform-python-devel-3.6.8-2.0.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-idle-3.6.8-2.0.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-libs-3.6.8-2.0.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-test-3.6.8-2.0.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-tkinter-3.6.8-2.0.1.el8_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "platform-python / platform-python-debug / platform-python-devel / etc");
}
