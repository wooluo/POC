##
# 
##

include('compat.inc');

if (description)
{
  script_id(141797);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id(
    "CVE-2020-14672",
    "CVE-2020-14760",
    "CVE-2020-14765",
    "CVE-2020-14769",
    "CVE-2020-14771",
    "CVE-2020-14775",
    "CVE-2020-14776",
    "CVE-2020-14789",
    "CVE-2020-14790",
    "CVE-2020-14793",
    "CVE-2020-14812",
    "CVE-2020-14827",
    "CVE-2020-14867",
    "CVE-2020-14869"
  );
  script_xref(name:"IAVA", value:"2020-A-0473");

  script_name(english:"MySQL 5.7.x < 5.7.32 Multiple Vulnerabilities (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to 5.7.32. It is, therefore, affected by multiple
vulnerabilities, including the following, as noted in the October 2020 Critical Patch Update advisory:
  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions 
  that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable 
  vulnerability allows low privileged attacker with network access via multiple protocols to compromise 
  MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a 
  hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2020-14765)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported 
  versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily 
  exploitable vulnerability allows low privileged attacker with network access via multiple protocols 
  to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized 
  ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2020-14769)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that
  are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows low 
  privileged attacker with network access via multiple protocols to compromise MySQL Server. 
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or 
  frequently repeatable crash (complete DOS) of MySQL Server (CVE-2020-14775). 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpuoct2020.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a84ed85");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(min:'5.7.0', fixed:'5.7.32', severity:SECURITY_WARNING);
