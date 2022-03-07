#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1714. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126611);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/11 12:05:32");

  script_cve_id("CVE-2019-6471");
  script_xref(name:"RHSA", value:"2019:1714");

  script_name(english:"RHEL 8 : bind (RHSA-2019:1714)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for bind is now available for Red Hat Enterprise Linux 8.

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
    value:"https://access.redhat.com/errata/RHSA-2019:1714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-6471"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-export-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs-lite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");
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
  rhsa = "RHSA-2019:1714";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-chroot-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-chroot-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-debugsource-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-debugsource-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-debugsource-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-export-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-export-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-export-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-export-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-export-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-export-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-export-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-export-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-export-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-libs-lite-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-libs-lite-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-libs-lite-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-libs-lite-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-libs-lite-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-libs-lite-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", reference:"bind-license-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-lite-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-lite-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-lite-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-pkcs11-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-pkcs11-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-pkcs11-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-pkcs11-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-pkcs11-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-pkcs11-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-pkcs11-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-pkcs11-devel-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-pkcs11-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-pkcs11-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-pkcs11-libs-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-pkcs11-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-pkcs11-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-pkcs11-libs-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-pkcs11-utils-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-pkcs11-utils-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-pkcs11-utils-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-pkcs11-utils-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-pkcs11-utils-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-sdb-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-sdb-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-sdb-chroot-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-sdb-chroot-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-sdb-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-sdb-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-sdb-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-utils-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-utils-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"bind-utils-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bind-utils-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bind-utils-debuginfo-9.11.4-17.P2.el8_0.1")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-bind-9.11.4-17.P2.el8_0.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-debugsource / bind-devel / etc");
  }
}
