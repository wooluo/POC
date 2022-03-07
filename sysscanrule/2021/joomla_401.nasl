
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152984);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id("CVE-2021-26040");
  script_xref(name:"IAVA", value:"2021-A-0400");

  script_name(english:"Joomla 4.0 < 4.0.1 Insufficient Access Control (5846-joomla-4-0-1)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by an insufficient access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 4.0 prior to 4.0.1.
It is, therefore, affected by an insufficient access control vulnerability on its com_media deletion endpoint. An 
unauthenticated, remote attacker could exploit this to delete arbitrary files on an affected system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.joomla.org/security-centre/861-20210801-core-insufficient-access-control-for-com-media-deletion-endpoint
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a1ea724");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26040");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/03");

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

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{'min_version': '4.0.0', 'fixed_version': '4.0.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
