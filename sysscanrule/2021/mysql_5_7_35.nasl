
##
# 
##



include('compat.inc');

if (description)
{
  script_id(151969);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id(
    "CVE-2019-17543",
    "CVE-2021-2342",
    "CVE-2021-2356",
    "CVE-2021-2372",
    "CVE-2021-2385",
    "CVE-2021-2389",
    "CVE-2021-2390",
    "CVE-2021-22901"
  );
  script_xref(name:"IAVA", value:"2021-A-0333");

  script_name(english:"MySQL 5.7.x < 5.7.35 Multiple Vulnerabilities (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to 5.7.35. It is, therefore, affected by multiple
vulnerabilities, including the following, as noted in the July 2021 Critical Patch Update advisory:

  - curl 7.75.0 through 7.76.1 suffers from a use-after-free vulnerability resulting in already freed memory being
  used when a TLS 1.3 session ticket arrives over a connection. A malicious server can use this in rare unfortunate
  circumstances to potentially reach remote code execution in the client. (CVE-2021-22901)

  - LZ4 before 1.9.2 has a heap-based buffer overflow in LZ4_write32 (related to LZ4_compress_destSize), affecting
  applications that call LZ4_compress_fast with a large input. (This issue can also lead to data corruption.)
  (CVE-2019-17543)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected
  are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows high privileged attacker with
  network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result
  in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
  (CVE-2021-2372)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.35 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

mysql_check_version(min:'5.7.0', fixed:'5.7.35', severity:SECURITY_WARNING);
