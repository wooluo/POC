#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126784);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/18 17:19:50");

  script_cve_id(
    "CVE-2019-2737",
    "CVE-2019-2738",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2741",
    "CVE-2019-2752",
    "CVE-2019-2757",
    "CVE-2019-2758",
    "CVE-2019-2774",
    "CVE-2019-2778",
    "CVE-2019-2780",
    "CVE-2019-2784",
    "CVE-2019-2785",
    "CVE-2019-2789",
    "CVE-2019-2791",
    "CVE-2019-2795",
    "CVE-2019-2796",
    "CVE-2019-2797",
    "CVE-2019-2800",
    "CVE-2019-2801",
    "CVE-2019-2802",
    "CVE-2019-2803",
    "CVE-2019-2805",
    "CVE-2019-2808",
    "CVE-2019-2810",
    "CVE-2019-2811",
    "CVE-2019-2812",
    "CVE-2019-2814",
    "CVE-2019-2815",
    "CVE-2019-2819",
    "CVE-2019-2822",
    "CVE-2019-2826",
    "CVE-2019-2830",
    "CVE-2019-2834",
    "CVE-2019-2879"
  );
  script_bugtraq_id(
    109234,
    109243,
    109247
  );
  script_xref(name:"IAVA", value:"2019-A-0252");

  script_name(english:"MySQL 8.0.x < 8.0.17 Multiple Vulnerabilities (July 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to
8.0.17. It is, therefore, affected by multiple vulnerabilities,
including three of the top vulnerabilities below, as noted in the
July 2019 Critical Patch Update advisory:

  - An unspecified vulnerability in the
    'Shell: Admin / InnoDB Cluster' subcomponent could allow
    an unauthenticated attacker to takeover an affected MySQL
    Server. A successful attack requires user interaction.
    (CVE-2019-2822)

  - As unspecified vulnerability in the 'Server: Replication'
    subcomponent could allow an unauthenticated attacker to
    cause the server to hang or to, via a frequently
    repeatable crash, cause a complete denial of service.
    Additionally, a successful attacker could perform
    unauthorized modifications to some MySQL Server
    accessible data. (CVE-2019-2800)

  - As unspecified vulnerability in the 'Server: Charsets'
    subcomponent could allow an unauthenticated attacker to
    cause the server to hang or to, via a frequently
    repeatable crash, cause a complete denial of service.
    (CVE-2019-2795)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.
");

  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-17.html");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2822");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

mysql_check_version(fixed:'8.0.17', min:'8.0', severity:SECURITY_WARNING);
