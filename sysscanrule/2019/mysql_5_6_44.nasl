#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124158);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 17:19:50");

  script_cve_id(
    "CVE-2019-1559",
    "CVE-2019-2683",
    "CVE-2019-2627",
    "CVE-2019-2614"
  );
  script_bugtraq_id(
    107174,
    107927
  );
  script_xref(name:"IAVA", value:"2019-A-0122");

  script_name(english:"MySQL 5.6.x < 5.6.44 Multiple Vulnerabilities (Apr 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to
5.6.44. It is, therefore, affected by multiple vulnerabilities,
including three of the top vulnerabilities below, as noted in the
April 2019 Critical Patch Update advisory:

  - An unspecified vulnerability in the
    'Server: Compiling (OpenSSL)' subcomponent could allow
    an unauthenticated attacker to gain complete access to
    all MySQL Server accessible data. (CVE-2019-1559)

  - An unspecified vulnerability in the 'Server: Options'
    subcomponent could allow a high privileged attacker to
    hang or to, via a frequently repeatable crash, cause a
    complete denial of service. (CVE-2019-2683)

  - An unspecified vulnerability in the
    'Server: Security: Privileges' subcomponent could allow
    a high privileged attacker to hang or to, via a
    frequently repeatable crash, cause a complete denial of
    service. (CVE-2019-2627)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.
");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-44.html");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"");

  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1559");

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

mysql_check_version(fixed:'5.6.44', min:'5.6', severity:SECURITY_WARNING);