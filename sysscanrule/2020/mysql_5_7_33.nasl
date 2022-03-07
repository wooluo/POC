##
# 
##

include('compat.inc');

if (description)
{
  script_id(145247);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/22");

  script_cve_id(
    "CVE-2021-2010",
    "CVE-2021-2011",
    "CVE-2021-2014",
    "CVE-2021-2022",
    "CVE-2021-2032",
    "CVE-2021-2060"
  );

  script_name(english:"MySQL 5.7.x < 5.7.33 Multiple Vulnerabilities (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to 5.7.33. It is, therefore, affected by multiple
vulnerabilities, including the following, as noted in the January 2021 Critical Patch Update advisory:

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
  affected are 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability allows unauthenticated
  attacker with network access via multiple protocols to compromise MySQL Client. Successful attacks of this
  vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of
  MySQL Client. (CVE-2021-2011)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PAM Auth Plugin). Supported
  versions that are affected are 5.7.32 and prior. Easily exploitable vulnerability allows high privileged
  attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
  vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
  Server. (CVE-2021-2014)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions
  that are affected are 5.6.50 and prior, 5.7.32 and prior and 8.0.22 and prior. Easily exploitable
  vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server. (CVE-2021-2060)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.33 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2011");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(min:'5.7.0', fixed:'5.7.33', severity:SECURITY_WARNING);
