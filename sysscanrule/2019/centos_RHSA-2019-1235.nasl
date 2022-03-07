#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1235 and 
# CentOS Errata and Security Advisory 2019:1235 respectively.
#

include("compat.inc");

if (description)
{
  script_id(125316);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/19 13:26:28");

  script_cve_id("CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_xref(name:"RHSA", value:"2019:1235");

  script_name(english:"CentOS 7 : ruby (CESA-2019:1235)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # https://lists.centos.org/pipermail/centos-announce/2019-May/023315.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-devel-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-doc-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-irb-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-libs-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-tcltk-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-bigdecimal-1.2.0-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-io-console-0.4.2-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-json-1.7.7-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-minitest-4.3.2-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-psych-2.0.0-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-rake-0.9.6-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-rdoc-4.0.0-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygems-2.0.14.1-35.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygems-devel-2.0.14.1-35.el7_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
