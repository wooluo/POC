#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2439 and 
# CentOS Errata and Security Advisory 2018:2439 respectively.
#

include("compat.inc");

if (description)
{
  script_id(112020);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/15 14:20:29");

  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3651", "CVE-2017-3653", "CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819", "CVE-2018-3133", "CVE-2019-2455");
  script_xref(name:"RHSA", value:"2018:2439");

  script_name(english:"CentOS 7 : mariadb (CESA-2018:2439)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for mariadb is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

The following packages have been upgraded to a later upstream version:
mariadb (5.5.60). (BZ#1584668, BZ#1584671, BZ#1584674, BZ#1601085)

Security Fix(es) :

* mysql: Client programs unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3636)

* mysql: Server: DML unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3641)

* mysql: Client mysqldump unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3651)

* mysql: Server: Replication unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10268)

* mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10378)

* mysql: Client programs unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10379)

* mysql: Server: DDL unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10384)

* mysql: Server: Partition unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2562)

* mysql: Server: DDL unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2622)

* mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2640)

* mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2665)

* mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2668)

* mysql: Server: Replication unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2755)

* mysql: Client programs unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2761)

* mysql: Server: Locking unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2771)

* mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2781)

* mysql: Server: DDL unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2813)

* mysql: Server: DDL unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2817)

* mysql: InnoDB unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2819)

* mysql: Server: DDL unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3653)

* mysql: use of SSL/TLS not enforced in libmysqld (Return of
BACKRONYM) (CVE-2018-2767)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Bug Fix(es) :

* Previously, the mysqladmin tool waited for an inadequate length of
time if the socket it listened on did not respond in a specific way.
Consequently, when the socket was used while the MariaDB server was
starting, the mariadb service became unresponsive for a long time.
With this update, the mysqladmin timeout has been shortened to 2
seconds. As a result, the mariadb service either starts or fails but
no longer hangs in the described situation. (BZ#1584023)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-August/022995.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-bench-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-devel-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-libs-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-server-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-test-5.5.60-1.el7_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
