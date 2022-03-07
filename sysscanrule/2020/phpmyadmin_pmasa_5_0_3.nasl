##
# 
##

include('compat.inc');

if (description)
{
  script_id(144649);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2020-26934", "CVE-2020-26935");

  script_name(english:"phpMyAdmin 4.9.0 < 4.9.6 / 5.0.0 < 5.0.3 Multiple Vulnerabilities (PMASA-2020-5, PMASA-2020-6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the phpMyAdmin application hosted on the remote web server is 4.9.x prior to
4.9.6 or 5.0.x prior to 5.0.3. It is, therefore, affected by multiple vulnerabilities.

  - phpMyAdmin before 4.9.6 and 5.x before 5.0.3 allows XSS through the transformation feature via a crafted
    link. (CVE-2020-26934)

  - An issue was discovered in SearchController in phpMyAdmin before 4.9.6 and 5.x before 5.0.3. A SQL
    injection vulnerability was discovered in how phpMyAdmin processes SQL statements in the search feature.
    An attacker could use this flaw to inject malicious SQL in to a query. (CVE-2020-26935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2020-5/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2020-6/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.9.6 / 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(661);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/31");

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
  { 'min_version' : '4.9.0', 'fixed_version' : '4.9.6' },
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE, sqli:TRUE});
