#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1815. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126941);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2842");
  script_xref(name:"RHSA", value:"2019:1815");

  script_name(english:"RHEL 7 : java-1.8.0-openjdk (RHSA-2019:1815)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: Side-channel attack risks in Elliptic Curve (EC)
cryptography (Security, 8208698) (CVE-2019-2745)

* OpenJDK: Insufficient checks of suppressed exceptions in
deserialization (Utilities, 8212328) (CVE-2019-2762)

* OpenJDK: Unbounded memory allocation during deserialization in
Collections (Utilities, 8213432) (CVE-2019-2769)

* OpenJDK: Missing URL format validation (Networking, 8221518)
(CVE-2019-2816)

* OpenJDK: Missing array bounds check in crypto providers (JCE,
8223511) (CVE-2019-2842)

* OpenJDK: Insufficient restriction of privileges in AccessController
(Security, 8216381) (CVE-2019-2786)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2842"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/23");
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
  rhsa = "RHSA-2019:1815";
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
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-accessibility-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-accessibility-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-demo-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-demo-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-devel-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-devel-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-headless-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-headless-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-src-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-src-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.8.0-openjdk-src-debug-1.8.0.222.b10-0.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.222.b10-0.el7_6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
  }
}