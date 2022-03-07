#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1972. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127642);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-8324");
  script_xref(name:"RHSA", value:"2019:1972");

  script_name(english:"RHEL 8 : ruby:2.5 (RHSA-2019:1972)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for the ruby:2.5 module is now available for Red Hat
Enterprise Linux 8.

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

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-8324"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bigdecimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-io-console-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mysql2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mysql2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-psych-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
  rhsa = "RHSA-2019:1972";
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
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"ruby-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"ruby-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"ruby-debuginfo-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"ruby-debuginfo-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-debuginfo-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"ruby-debugsource-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"ruby-debugsource-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-debugsource-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"ruby-devel-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"ruby-devel-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-devel-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"ruby-doc-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"ruby-irb-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"ruby-libs-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"ruby-libs-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-libs-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"ruby-libs-debuginfo-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"ruby-libs-debuginfo-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-libs-debuginfo-2.5.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-abrt-0.3.0-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-abrt-doc-0.3.0-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-bigdecimal-1.3.4-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-bigdecimal-1.3.4-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-bigdecimal-1.3.4-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-bigdecimal-debuginfo-1.3.4-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-bigdecimal-debuginfo-1.3.4-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-bigdecimal-debuginfo-1.3.4-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-bson-4.3.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-bson-4.3.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-bson-debuginfo-4.3.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-bson-debuginfo-4.3.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-bson-debugsource-4.3.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-bson-debugsource-4.3.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-bson-doc-4.3.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-bundler-1.16.1-3.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-bundler-doc-1.16.1-3.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-did_you_mean-1.2.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-io-console-0.4.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-io-console-0.4.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-io-console-0.4.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-io-console-debuginfo-0.4.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-io-console-debuginfo-0.4.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-io-console-debuginfo-0.4.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-json-2.1.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-json-2.1.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-json-2.1.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-json-debuginfo-2.1.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-json-debuginfo-2.1.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-json-debuginfo-2.1.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-minitest-5.10.3-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-mongo-2.5.1-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-mongo-doc-2.5.1-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-mysql2-0.4.10-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-mysql2-0.4.10-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-mysql2-debuginfo-0.4.10-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-mysql2-debuginfo-0.4.10-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-mysql2-debugsource-0.4.10-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-mysql2-debugsource-0.4.10-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-mysql2-doc-0.4.10-4.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-net-telnet-0.1.1-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-openssl-2.1.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-openssl-2.1.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-openssl-2.1.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-openssl-debuginfo-2.1.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-openssl-debuginfo-2.1.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-openssl-debuginfo-2.1.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-pg-1.0.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-pg-1.0.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-pg-debuginfo-1.0.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-pg-debuginfo-1.0.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-pg-debugsource-1.0.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-pg-debugsource-1.0.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-pg-doc-1.0.0-2.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-power_assert-1.1.1-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-psych-3.0.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-psych-3.0.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-psych-3.0.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-psych-debuginfo-3.0.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-psych-debuginfo-3.0.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-psych-debuginfo-3.0.2-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-rake-12.3.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-rdoc-6.0.1-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-test-unit-3.2.7-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-xmlrpc-0.3.0-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygems-2.7.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygems-devel-2.7.6-104.module+el8.0.0+3250+4b7d6d43")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-debugsource / ruby-devel / ruby-doc / etc");
  }
}
