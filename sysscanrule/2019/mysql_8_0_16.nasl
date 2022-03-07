#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124160);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 17:19:50");

  script_cve_id(
    "CVE-2019-1559",
    "CVE-2019-2566",
    "CVE-2019-2580",
    "CVE-2019-2581",
    "CVE-2019-2584",
    "CVE-2019-2585",
    "CVE-2019-2587",
    "CVE-2019-2589",
    "CVE-2019-2592",
    "CVE-2019-2593",
    "CVE-2019-2596",
    "CVE-2019-2606",
    "CVE-2019-2607",
    "CVE-2019-2614",
    "CVE-2019-2617",
    "CVE-2019-2620",
    "CVE-2019-2623",
    "CVE-2019-2624",
    "CVE-2019-2625",
    "CVE-2019-2626",
    "CVE-2019-2627",
    "CVE-2019-2628",
    "CVE-2019-2630",
    "CVE-2019-2631",
    "CVE-2019-2632",
    "CVE-2019-2634",
    "CVE-2019-2635",
    "CVE-2019-2636",
    "CVE-2019-2644",
    "CVE-2019-2681",
    "CVE-2019-2683",
    "CVE-2019-2685",
    "CVE-2019-2686",
    "CVE-2019-2687",
    "CVE-2019-2688",
    "CVE-2019-2689",
    "CVE-2019-2691",
    "CVE-2019-2693",
    "CVE-2019-2694",
    "CVE-2019-2695",
    "CVE-2019-2755",
    "CVE-2019-2798",
    "CVE-2019-3822",
    "CVE-2018-16890",
    "CVE-2019-3823"
  );
  script_bugtraq_id(
    106950,
    107174,
    107913,
    107924,
    107927,
    107928,
    109259,
    109260
  );
  script_xref(name:"IAVA", value:"2019-A-0122");

  script_name(english:"MySQL 8.0.x < 8.0.16 Multiple Vulnerabilities (Apr 2019 CPU) (Jul 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to
8.0.16. It is, therefore, affected by multiple vulnerabilities,
including four of the top vulnerabilities below, as noted in the
April 2019 and July 2019 Critical Patch Update advisories:

  - An unspecified vulnerability in the 'Server: Packaging
    (cURL)' subcomponent could allow an unauthenticated
    attacker to gain complete control of an affected instance
    of MySQL Server. (CVE-2019-3822)

  - An unspecified vulnerability in the 'Server: Pluggable
    Auth' subcomponent could allow an unauthenticated
    attacker to gain complete access to all MySQL Server
    accessible data. (CVE-2019-2632)

  - Multiple denial of service vulnerabilities exist in the
    'Server: Optimizer' subcomponent and could allow a low
    priviledged attacker to cause the server to hang or to,
    via a frequently repeatable crash, cause a complete
    denial of service. (CVE-2019-2693, CVE-2019-2694,
    CVE-2019-2695)

  - An unspecified vulnerability in the
    'Server: Compiling (OpenSSL)' subcomponent could allow
    an unauthenticated attacker to gain complete access to
    all MySQL Server accessible data. (CVE-2019-1559)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.
");

  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-16.html");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3822");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'8.0.16', min:'8.0', severity:SECURITY_HOLE);
