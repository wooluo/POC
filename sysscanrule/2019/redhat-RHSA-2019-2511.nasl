#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2511. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127991);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-2420", "CVE-2019-2434", "CVE-2019-2436", "CVE-2019-2455", "CVE-2019-2481", "CVE-2019-2482", "CVE-2019-2486", "CVE-2019-2494", "CVE-2019-2495", "CVE-2019-2502", "CVE-2019-2503", "CVE-2019-2507", "CVE-2019-2510", "CVE-2019-2528", "CVE-2019-2529", "CVE-2019-2530", "CVE-2019-2531", "CVE-2019-2532", "CVE-2019-2533", "CVE-2019-2534", "CVE-2019-2535", "CVE-2019-2536", "CVE-2019-2537", "CVE-2019-2539", "CVE-2019-2580", "CVE-2019-2581", "CVE-2019-2584", "CVE-2019-2585", "CVE-2019-2587", "CVE-2019-2589", "CVE-2019-2592", "CVE-2019-2593", "CVE-2019-2596", "CVE-2019-2606", "CVE-2019-2607", "CVE-2019-2614", "CVE-2019-2617", "CVE-2019-2620", "CVE-2019-2623", "CVE-2019-2624", "CVE-2019-2625", "CVE-2019-2626", "CVE-2019-2627", "CVE-2019-2628", "CVE-2019-2630", "CVE-2019-2631", "CVE-2019-2634", "CVE-2019-2635", "CVE-2019-2636", "CVE-2019-2644", "CVE-2019-2681", "CVE-2019-2683", "CVE-2019-2685", "CVE-2019-2686", "CVE-2019-2687", "CVE-2019-2688", "CVE-2019-2689", "CVE-2019-2691", "CVE-2019-2693", "CVE-2019-2694", "CVE-2019-2695", "CVE-2019-2737", "CVE-2019-2738", "CVE-2019-2739", "CVE-2019-2740", "CVE-2019-2752", "CVE-2019-2755", "CVE-2019-2757", "CVE-2019-2758", "CVE-2019-2774", "CVE-2019-2778", "CVE-2019-2780", "CVE-2019-2784", "CVE-2019-2785", "CVE-2019-2789", "CVE-2019-2795", "CVE-2019-2796", "CVE-2019-2797", "CVE-2019-2798", "CVE-2019-2800", "CVE-2019-2801", "CVE-2019-2802", "CVE-2019-2803", "CVE-2019-2805", "CVE-2019-2808", "CVE-2019-2810", "CVE-2019-2811", "CVE-2019-2812", "CVE-2019-2814", "CVE-2019-2815", "CVE-2019-2819", "CVE-2019-2826", "CVE-2019-2830", "CVE-2019-2834", "CVE-2019-2879");
  script_xref(name:"RHSA", value:"2019:2511");

  script_name(english:"RHEL 8 : mysql:8.0 (RHSA-2019:2511)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for the mysql:8.0 module is now available for Red Hat
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
    value:"https://access.redhat.com/errata/RHSA-2019:2511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2879"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
  rhsa = "RHSA-2019:2511";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mecab-0.996-1.module+el8.0.0+3898+e09bb8de.9")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mecab-0.996-1.module+el8.0.0+3898+e09bb8de.9")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mecab-debuginfo-0.996-1.module+el8.0.0+3898+e09bb8de.9")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mecab-debuginfo-0.996-1.module+el8.0.0+3898+e09bb8de.9")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mecab-debugsource-0.996-1.module+el8.0.0+3898+e09bb8de.9")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mecab-debugsource-0.996-1.module+el8.0.0+3898+e09bb8de.9")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-common-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-common-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-debugsource-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-debugsource-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-devel-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-devel-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-devel-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-devel-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-errmsg-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-errmsg-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-libs-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-libs-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-libs-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-libs-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-server-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-server-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-server-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-server-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-test-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-test-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mysql-test-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mysql-test-debuginfo-8.0.17-3.module+el8.0.0+3898+e09bb8de")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mecab / mecab-debuginfo / mecab-debugsource / mecab-ipadic / etc");
  }
}
