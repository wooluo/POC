##
# 
##

include('compat.inc');

if (description)
{
  script_id(144641);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/31");

  script_cve_id("CVE-2015-8669");
  script_bugtraq_id(79691);

  script_name(english:"phpMyAdmin 4.0.0 < 4.0.10.12 / 4.4.0 < 4.4.15.2 / 4.5.0 < 4.5.3.1 Information Disclosure (PMASA-2015-6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the phpMyAdmin application hosted on the remote web server is 4.0.x prior to
4.0.10.12, 4.4.x prior to 4.4.15.2, or 4.5.x prior to 4.5.3.1. It is, therefore, affected by an information disclosure
vulnerability:

  - libraries/config/messages.inc.php in phpMyAdmin 4.0.x before 4.0.10.12, 4.4.x before 4.4.15.2, and 4.5.x
    before 4.5.3.1 allows remote attackers to obtain sensitive information via a crafted request, which
    reveals the full path in an error message. (CVE-2015-8669)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2015-6/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.0.10.12 / 4.4.15.2 / 4.5.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8669");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200, 661);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '4.0.0', 'fixed_version' : '4.0.10.12' },
  { 'min_version' : '4.4.0', 'fixed_version' : '4.4.15.2' },
  { 'min_version' : '4.5.0', 'fixed_version' : '4.5.3.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
