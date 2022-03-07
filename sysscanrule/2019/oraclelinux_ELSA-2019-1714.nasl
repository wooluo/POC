#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1714 and 
# Oracle Linux Security Advisory ELSA-2019-1714 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127597);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-6471");
  script_xref(name:"RHSA", value:"2019:1714");

  script_name(english:"Oracle Linux 8 : bind (ELSA-2019-1714)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:1714 :

An update for bind is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

Security Fix(es) :

* bind: Race condition when discarding malformed packets can cause
bind to exit with assertion failure (CVE-2019-6471)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008983.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-chroot-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-devel-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-export-devel-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-export-libs-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-libs-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-libs-lite-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-license-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-lite-devel-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-pkcs11-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-pkcs11-devel-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-pkcs11-libs-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-pkcs11-utils-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-sdb-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-sdb-chroot-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bind-utils-9.11.4-17.P2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-bind-9.11.4-17.P2.el8_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-export-devel / etc");
}
