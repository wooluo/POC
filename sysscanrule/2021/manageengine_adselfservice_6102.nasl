
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152680);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/20");

  script_cve_id("CVE-2021-28958");

  script_name(english:"ManageEngine ADSelfService Plus < Build 6102 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine ADSelfService Plus running on the remote
host is prior to build 6102. It is, therefore, affected by a remote
code execution vulnerability while changing the password.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported build number.");
  # https://pitstop.manageengine.com/portal/en/community/topic/adselfservice-plus-6102-released-with-an-important-security-fix-21-3-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1168f5e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADSelfService Plus build 6102 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28958");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 Tenable Network Security, Inc.");

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
  app     : app,
  port    : port,
  webapp  : TRUE
);

constraints = [
  { 'fixed_version':'6102', 'fixed_display': '6.1, build 6102'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

