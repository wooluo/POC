#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121229);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/18 14:32:48");

  script_cve_id(
    "CVE-2018-0734",
    "CVE-2019-2420",
    "CVE-2019-2434",
    "CVE-2019-2436",
    "CVE-2019-2455",
    "CVE-2019-2481",
    "CVE-2019-2482",
    "CVE-2019-2486",
    "CVE-2019-2494",
    "CVE-2019-2495",
    "CVE-2019-2502",
    "CVE-2019-2503",
    "CVE-2019-2507",
    "CVE-2019-2510",
    "CVE-2019-2513",
    "CVE-2019-2528",
    "CVE-2019-2529",
    "CVE-2019-2530",
    "CVE-2019-2531",
    "CVE-2019-2532",
    "CVE-2019-2533",
    "CVE-2019-2534",
    "CVE-2019-2535",
    "CVE-2019-2536",
    "CVE-2019-2537",
    "CVE-2019-2539",
    "CVE-2018-3123"
  );
  script_bugtraq_id(
    105758,
    106619,
    106622,
    106625,
    106626,
    106627,
    106628
  );

  script_name(english:"MySQL 8.0.x < 8.0.14 Multiple Vulnerabilities (Jan 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to
8.0.14. It is, therefore, affected by multiple vulnerabilities,
including three of the top vulnerabilities below, as noted in the
January 2019 Critical Patch Update advisory:

  - An unspecified vulnerability in MySQL in the
    'Server: Replication' subcomponent could allow an low
    privileged attacker with network access via multiple
    protocols to gain unauthorized access critical data or
    complete access to all MySQL server data. (CVE-2019-2534)

  - An unspecified vulnerability in MySQL in the
    'Server: Optimizer' subcomponent could allow an low
    privileged attacker with network access via multiple
    protocols to perform a denial of service attack.
    (CVE-2019-2529)

  - An unspecified vulnerability in MySQL in the
    'Server: PS' subcomponent could allow an low
    privileged attacker with network access via multiple
    protocols to perform a denial of service attack.
    (CVE-2019-2482)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-14.html");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2534");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'8.0.14', min:'8.0', severity:SECURITY_HOLE);
