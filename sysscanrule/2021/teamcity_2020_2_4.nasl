
##
# 
##


include('compat.inc');

if (description)
{
  script_id(151791);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2020-7908",
    "CVE-2020-7909",
    "CVE-2020-7910",
    "CVE-2020-7911",
    "CVE-2020-11686",
    "CVE-2020-11687",
    "CVE-2020-11688",
    "CVE-2020-11689",
    "CVE-2020-11938",
    "CVE-2020-15826",
    "CVE-2021-3315",
    "CVE-2021-26309",
    "CVE-2021-26310",
    "CVE-2021-31904",
    "CVE-2021-31906",
    "CVE-2021-31907",
    "CVE-2021-31908",
    "CVE-2021-31909",
    "CVE-2021-31910",
    "CVE-2021-31911",
    "CVE-2021-31912",
    "CVE-2021-31913",
    "CVE-2021-31914",
    "CVE-2021-31915"
  );
  script_xref(name:"IAVA", value:"2021-A-0308");
  
  script_name(english:"TeamCity Server < 2020.2.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of JetBrains TeamCity running on the
remote host is a version prior to 2020.2.4. It is, therefore, affected by
multiple vulnerabilities:
    
  - A command injection vulnerability exists in JetBrains TeamCity. An unauthenticated, remote
    attacker can exploit this to execute arbitrary commands. (CVE-2021-31915)

  - An arbitrary code execution vulnerability exists in JetBrains TeamCity. An unauthenticated, 
    remote attacker can exploit this to bypass authentication and execute arbitrary commands. (CVE-2021-31914)

  - A remote code execution vulnerability exists in JetBrains TeamCity. An unauthenticated, 
    remote attacker can exploit this to bypass authentication and execute arbitrary commands. (CVE-2021-31909)

Note that Nessus did not actually test for these issues, but instead
has relied on the version found in the server's banner.");
  # https://blog.jetbrains.com/blog/2021/05/07/jetbrains-security-bulletin-q1-2021/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cd4a6be");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains TeamCity version 2020.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31915");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:teamcity");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_teamcity_web_detect.nbin");
  script_require_keys("installed_sw/JetBrains TeamCity");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'JetBrains TeamCity', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '2020.2.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
