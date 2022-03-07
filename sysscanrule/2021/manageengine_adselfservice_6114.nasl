
##
# 
##


include('compat.inc');

if (description)
{
  script_id(153147);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/09");

  script_cve_id("CVE-2021-40539");

  script_name(english:"ManageEngine ADSelfService Plus < build 6114 REST API Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the ManageEngine ADSelfService Plus application running on the remote host is
prior to build 6114. It is, therefore, affected by an authentication bypass vulnerability affecting REST API URLs. An
unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported build
number.");
  # https://www.manageengine.com/products/self-service-password/kb/how-to-fix-authentication-bypass-vulnerability-in-REST-API.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74285241");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADSelfService Plus build 6114 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40539");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_adselfservice_detect.nasl");
  script_require_keys("installed_sw/ManageEngine ADSelfService Plus");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app, app_info, constraints, port;

app = 'ManageEngine ADSelfService Plus';

# Exit if app is not detected on this http port
port = get_http_port(default:8888);

app_info = vcf::get_app_info(
  app: app,
  port:  port,
  webapp: TRUE
);

constraints = [
  { 'fixed_version':'6114', 'fixed_display':'build 6114'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

