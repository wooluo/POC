#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:0482 and 
# Oracle Linux Security Advisory ELSA-2019-0482 respectively.
#

include("compat.inc");

if (description)
{
  script_id(122801);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/04 11:19:02");

  script_cve_id("CVE-2019-3804");
  script_xref(name:"RHSA", value:"2019:0482");

  script_name(english:"Oracle Linux 7 : cockpit (ELSA-2019-0482)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:0482 :

An update for cockpit is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Cockpit enables users to administer GNU/Linux servers using a web
browser. It offers network configuration, log inspection, diagnostic
reports, SELinux troubleshooting, interactive command-line sessions,
and more.

Security Fix(es) :

* cockpit: Crash when parsing invalid base64 headers (CVE-2019-3804)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-March/008526.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cockpit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-machines-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-ws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/13");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cockpit-173.2-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cockpit-bridge-173.2-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cockpit-doc-173.2-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cockpit-machines-ovirt-173.2-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cockpit-system-173.2-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cockpit-ws-173.2-1.0.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cockpit / cockpit-bridge / cockpit-doc / cockpit-machines-ovirt / etc");
}
