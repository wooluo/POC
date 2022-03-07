##
# 
##

include('compat.inc');

if (description)
{
  script_id(144646);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2020-10802", "CVE-2020-10803", "CVE-2020-10804");

  script_name(english:"phpMyAdmin 4.9.0 < 4.9.5 / 5.0.0 < 5.0.2 Multiple Vulnerabilities (PMASA-2020-2, PMASA-2020-3, PMASA-2020-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the phpMyAdmin application hosted on the remote web server is 4.9.x prior to
4.9.5 or 5.0.x prior to 5.0.2. It is, therefore, affected by multiple vulnerabilities.

  - In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability was found in retrieval
    of the current username (in libraries/classes/Server/Privileges.php and
    libraries/classes/UserPassword.php). A malicious user with access to the server could create a crafted
    username, and then trick the victim into performing specific actions with that user account (such as
    editing its privileges). (CVE-2020-10804)

  - In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability has been discovered
    where certain parameters are not properly escaped when generating certain queries for search actions in
    libraries/classes/Controllers/Table/TableSearchController.php. An attacker can generate a crafted database
    or table name. The attack can be performed if a user attempts certain search operations on the malicious
    database or table. (CVE-2020-10802)

  - In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability was discovered where
    malicious code could be used to trigger an XSS attack through retrieving and displaying results (in
    tbl_get_field.php and libraries/classes/Display/Results.php). The attacker must be able to insert crafted
    data into certain database tables, which when retrieved (for instance, through the Browse tab) can trigger
    the XSS attack. (CVE-2020-10803)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2020-2/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2020-3/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2020-4/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.9.5 / 5.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(661);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'phpMyAdmin', port:port, webapp:TRUE);

constraints = [
  { 'min_version' : '4.9.0', 'fixed_version' : '4.9.5' },
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{sqli:TRUE});
