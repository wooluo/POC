#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1477. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125940);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/02 12:46:54");

  script_cve_id("CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5835", "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840");
  script_xref(name:"RHSA", value:"2019:1477");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2019:1477)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for chromium-browser is now available for Red Hat Enterprise
Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Chromium is an open source web browser, powered by WebKit (Blink).

This update upgrades Chromium to version 75.0.3770.80.

Security Fix(es) :

* chromium-browser: Use after free in ServiceWorker (CVE-2019-5828)

* chromium-browser: Use after free in Download Manager (CVE-2019-5829)

* chromium-browser: Incorrectly credentialed requests in CORS
(CVE-2019-5830)

* chromium-browser: Incorrect map processing in V8 (CVE-2019-5831)

* chromium-browser: Incorrect CORS handling in XHR (CVE-2019-5832)

* chromium-browser: Inconsistent security UI placement (CVE-2019-5833)

* chromium-browser: Out of bounds read in Swiftshader (CVE-2019-5835)

* chromium-browser: Heap buffer overflow in Angle (CVE-2019-5836)

* chromium-browser: Cross-origin resources size disclosure in Appcache
(CVE-2019-5837)

* chromium-browser: Overly permissive tab access in Extensions
(CVE-2019-5838)

* chromium-browser: Incorrect handling of certain code points in Blink
(CVE-2019-5839)

* chromium-browser: Popup blocker bypass (CVE-2019-5840)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5840"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected chromium-browser and / or
chromium-browser-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/17");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1477";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-75.0.3770.80-1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-75.0.3770.80-1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-debuginfo-75.0.3770.80-1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-debuginfo-75.0.3770.80-1.el6_10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium-browser / chromium-browser-debuginfo");
  }
}
