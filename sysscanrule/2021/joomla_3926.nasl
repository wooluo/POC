##
# 
##

include('compat.inc');

if (description)
{
  script_id(148641);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2021-26030", "CVE-2021-26031");
  script_xref(name:"IAVA", value:"2021-A-0179");

  script_name(english:"Joomla 3.0.x < 3.9.26 Multiple Vulnerabilities (5835-joomla-3-9-26)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.0.x prior to
3.9.26. It is, therefore, affected by multiple vulnerabilities:

  - A cross-site scripting (XSS) vulnerability exists in the logo parameter of the default templates page due to 
  improper validation of user-supplied input before returning it to users. An unauthenticated, remote attacker can 
  exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's
  browser session (CVE-2021-26030).

  - A local file inclusion vulnerability exists on the module layout settings component. An unauthenticated, remote 
  attacker may be able to leverage this issue to view arbitrary files or to execute arbitrary PHP code on the remote
  host (CVE-2021-26031).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://www.joomla.org/announcements/release-news/5835-joomla-3-9-26.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fbda47c");
  # https://developer.joomla.org/security-centre/850-20210401-core-escape-xss-in-logo-parameter-error-pages.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27b06c66");
  # https://developer.joomla.org/security-centre/851-20210402-core-inadequate-filters-on-module-layout-settings.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e407311a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{ 'min_version' : '3.0.0', 'max_version' : '3.9.25', 'fixed_version' : '3.9.26' }];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING, 
  flags:{'xss':TRUE}
);
