#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2511 and 
# Oracle Linux Security Advisory ELSA-2019-2511 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127983);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-2420", "CVE-2019-2434", "CVE-2019-2436", "CVE-2019-2455", "CVE-2019-2481", "CVE-2019-2482", "CVE-2019-2486", "CVE-2019-2494", "CVE-2019-2495", "CVE-2019-2502", "CVE-2019-2503", "CVE-2019-2507", "CVE-2019-2510", "CVE-2019-2528", "CVE-2019-2529", "CVE-2019-2530", "CVE-2019-2531", "CVE-2019-2532", "CVE-2019-2533", "CVE-2019-2534", "CVE-2019-2535", "CVE-2019-2536", "CVE-2019-2537", "CVE-2019-2539", "CVE-2019-2580", "CVE-2019-2581", "CVE-2019-2584", "CVE-2019-2585", "CVE-2019-2587", "CVE-2019-2589", "CVE-2019-2592", "CVE-2019-2593", "CVE-2019-2596", "CVE-2019-2606", "CVE-2019-2607", "CVE-2019-2614", "CVE-2019-2617", "CVE-2019-2620", "CVE-2019-2623", "CVE-2019-2624", "CVE-2019-2625", "CVE-2019-2626", "CVE-2019-2627", "CVE-2019-2628", "CVE-2019-2630", "CVE-2019-2631", "CVE-2019-2634", "CVE-2019-2635", "CVE-2019-2636", "CVE-2019-2644", "CVE-2019-2681", "CVE-2019-2683", "CVE-2019-2685", "CVE-2019-2686", "CVE-2019-2687", "CVE-2019-2688", "CVE-2019-2689", "CVE-2019-2691", "CVE-2019-2693", "CVE-2019-2694", "CVE-2019-2695", "CVE-2019-2737", "CVE-2019-2738", "CVE-2019-2739", "CVE-2019-2740", "CVE-2019-2752", "CVE-2019-2755", "CVE-2019-2757", "CVE-2019-2758", "CVE-2019-2774", "CVE-2019-2778", "CVE-2019-2780", "CVE-2019-2784", "CVE-2019-2785", "CVE-2019-2789", "CVE-2019-2795", "CVE-2019-2796", "CVE-2019-2797", "CVE-2019-2798", "CVE-2019-2800", "CVE-2019-2801", "CVE-2019-2802", "CVE-2019-2803", "CVE-2019-2805", "CVE-2019-2808", "CVE-2019-2810", "CVE-2019-2811", "CVE-2019-2812", "CVE-2019-2814", "CVE-2019-2815", "CVE-2019-2819", "CVE-2019-2826", "CVE-2019-2830", "CVE-2019-2834", "CVE-2019-2879");
  script_xref(name:"RHSA", value:"2019:2511");

  script_name(english:"Oracle Linux 8 : mysql:8.0 (ELSA-2019-2511)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:2511 :

An update for the mysql:8.0 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon, mysqld, and many client programs.

The following packages have been upgraded to a later upstream version:
mysql (8.0.17).

Security Fix(es) :

* mysql: Server: Replication multiple unspecified vulnerabilities
(CVE-2019-2800, CVE-2019-2436, CVE-2019-2531, CVE-2019-2534,
CVE-2019-2614, CVE-2019-2617, CVE-2019-2630, CVE-2019-2634,
CVE-2019-2635, CVE-2019-2755)

* mysql: Server: Optimizer multiple unspecified vulnerabilities
(CVE-2019-2420, CVE-2019-2481, CVE-2019-2507, CVE-2019-2529,
CVE-2019-2530, CVE-2019-2581, CVE-2019-2596, CVE-2019-2607,
CVE-2019-2625, CVE-2019-2681, CVE-2019-2685, CVE-2019-2686,
CVE-2019-2687, CVE-2019-2688, CVE-2019-2689, CVE-2019-2693,
CVE-2019-2694, CVE-2019-2695, CVE-2019-2757, CVE-2019-2774,
CVE-2019-2796, CVE-2019-2802, CVE-2019-2803, CVE-2019-2808,
CVE-2019-2810, CVE-2019-2812, CVE-2019-2815, CVE-2019-2830,
CVE-2019-2834)

* mysql: Server: Parser multiple unspecified vulnerabilities
(CVE-2019-2434, CVE-2019-2455, CVE-2019-2805)

* mysql: Server: PS multiple unspecified vulnerabilities
(CVE-2019-2482, CVE-2019-2592)

* mysql: Server: Security: Privileges multiple unspecified
vulnerabilities (CVE-2019-2486, CVE-2019-2532, CVE-2019-2533,
CVE-2019-2584, CVE-2019-2589, CVE-2019-2606, CVE-2019-2620,
CVE-2019-2627, CVE-2019-2739, CVE-2019-2778, CVE-2019-2811,
CVE-2019-2789)

* mysql: Server: DDL multiple unspecified vulnerabilities
(CVE-2019-2494, CVE-2019-2495, CVE-2019-2537, CVE-2019-2626,
CVE-2019-2644)

* mysql: InnoDB multiple unspecified vulnerabilities (CVE-2019-2502,
CVE-2019-2510, CVE-2019-2580, CVE-2019-2585, CVE-2019-2593,
CVE-2019-2624, CVE-2019-2628, CVE-2019-2758, CVE-2019-2785,
CVE-2019-2798, CVE-2019-2879, CVE-2019-2814)

* mysql: Server: Connection Handling unspecified vulnerability
(CVE-2019-2503)

* mysql: Server: Partition multiple unspecified vulnerabilities
(CVE-2019-2528, CVE-2019-2587)

* mysql: Server: Options multiple unspecified vulnerabilities
(CVE-2019-2535, CVE-2019-2623, CVE-2019-2683, CVE-2019-2752)

* mysql: Server: Packaging unspecified vulnerability (CVE-2019-2536)

* mysql: Server: Connection unspecified vulnerability (CVE-2019-2539)

* mysql: Server: Information Schema unspecified vulnerability
(CVE-2019-2631)

* mysql: Server: Group Replication Plugin unspecified vulnerability
(CVE-2019-2636)

* mysql: Server: Security: Roles multiple unspecified vulnerabilities
(CVE-2019-2691, CVE-2019-2826)

* mysql: Server: Pluggable Auth unspecified vulnerability
(CVE-2019-2737)

* mysql: Server: XML unspecified vulnerability (CVE-2019-2740)

* mysql: Server: Components / Services unspecified vulnerability
(CVE-2019-2780)

* mysql: Server: DML unspecified vulnerability (CVE-2019-2784)

* mysql: Server: Charsets unspecified vulnerability (CVE-2019-2795)

* mysql: Client programs unspecified vulnerability (CVE-2019-2797)

* mysql: Server: FTS unspecified vulnerability (CVE-2019-2801)

* mysql: Server: Security: Audit unspecified vulnerability
(CVE-2019-2819)

* mysql: Server: Compiling unspecified vulnerability (CVE-2019-2738)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/009076.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql:8.0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mecab-0.996-1.module+el8.0.0+5253+1dce7bb2.9")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mecab-ipadic-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mecab-ipadic-EUCJP-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mysql-8.0.17-3.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mysql-common-8.0.17-3.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mysql-devel-8.0.17-3.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mysql-errmsg-8.0.17-3.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mysql-libs-8.0.17-3.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mysql-server-8.0.17-3.module+el8.0.0+5253+1dce7bb2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mysql-test-8.0.17-3.module+el8.0.0+5253+1dce7bb2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mecab / mecab-ipadic / mecab-ipadic-EUCJP / mysql / mysql-common / etc");
}
