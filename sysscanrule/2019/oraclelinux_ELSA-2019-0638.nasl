#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:0638 and 
# Oracle Linux Security Advisory ELSA-2019-0638 respectively.
#

include("compat.inc");

if (description)
{
  script_id(123122);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/26 10:40:14");

  script_cve_id("CVE-2019-3816");
  script_xref(name:"RHSA", value:"2019:0638");

  script_name(english:"Oracle Linux 7 : openwsman (ELSA-2019-0638)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:0638 :

An update for openwsman is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Openwsman is a project intended to provide an open source
implementation of the Web Services Management specification
(WS-Management) and to expose system management information on the
Linux operating system using the WS-Management protocol. WS-Management
is based on a suite of web services specifications and usage
requirements that cover all system management aspects.

Security Fix(es) :

* openwsman: Disclosure of arbitrary files outside of the registered
URIs (CVE-2019-3816)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-March/008600.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openwsman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwsman-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwsman1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openwsman-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openwsman-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openwsman-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openwsman-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openwsman-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/26");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwsman-devel-2.6.3-6.git4391e5c.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwsman1-2.6.3-6.git4391e5c.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openwsman-client-2.6.3-6.git4391e5c.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openwsman-perl-2.6.3-6.git4391e5c.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openwsman-python-2.6.3-6.git4391e5c.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openwsman-ruby-2.6.3-6.git4391e5c.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openwsman-server-2.6.3-6.git4391e5c.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwsman-devel / libwsman1 / openwsman-client / openwsman-perl / etc");
}
