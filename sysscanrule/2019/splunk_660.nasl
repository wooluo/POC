#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126702);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/16  6:12:12");

  script_cve_id("CVE-2019-5727");
  script_bugtraq_id(107113);

  script_name(english:"Splunk Enterprise 6.0.x < 6.0.15, 6.1.x < 6.1.14, 6.2.x < 6.2.14, 6.3.x < 6.3.12, 6.4.x < 6.4.9, 6.5.x < 6.5.5 or Splunk Light < 6.6.0 Persistent XSS");
  script_summary(english:"Checks the version of Splunk Enterprise and Splunk Light");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a persistent cross-site scripting vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk running on the remote web server is Splunk
Enterprise 6.0.x prior to 6.0.15, 6.1.x prior to 6.1.14, 6.2.x prior to 6.2.14, 6.3.x prior to 6.3.12, 6.4.x prior to
6.4.9, 6.5.x prior to 6.5.5 or Splunk Light prior to 6.6.0.

It is, therefore, affected by a persistent XSS vulnerability due to improperly validated user-supplied input.
(CVE-2019-5727) An attacker can leverage this issue to execute arbitrary script code in the browser of an unsuspecting
user in the context of the affected site.

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAQAF");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 6.0.15 / 6.1.14 / 6.2.14 / 6.3.12 / 6.4.9 / 6.5.5 or later or Splunk Light to
version 6.6.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5727");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089, 8000);

  exit(0);
}

include('vcf.inc');
include('http.inc');
include('audit.inc');
include('global_settings.inc');

app = 'Splunk';
port = get_http_port(default:8000);

app_info = vcf::get_app_info(app:app, port:port);

# Enterprise affected:
# 6.5.x prior to 6.5.5
# 6.4.x prior to 6.4.9
# 6.3.x prior to 6.3.12
# 6.2.x prior to 6.2.14
# 6.1.x prior to 6.1.14
# 6.0.x prior to 6.0.15
if (app_info['License'] == 'Enterprise')
{
  constraints = [
    { 'min_version' : '6.0.0', 'fixed_version' : '6.0.15' },
    { 'min_version' : '6.1.0', 'fixed_version' : '6.1.14' },
    { 'min_version' : '6.2.0', 'fixed_version' : '6.2.14' },
    { 'min_version' : '6.3.0', 'fixed_version' : '6.3.12' },
    { 'min_version' : '6.4.0', 'fixed_version' : '6.4.9' },
    { 'min_version' : '6.5.0', 'fixed_version' : '6.5.5' }
    ];
}
# Light affected < 6.6.0
else if (app_info['License'] == 'Light')
{
  constraints = [
    { 'fixed_version' : '6.6.0' }
    ];
}
# Other license or no license, report not vulnerable
else {
  audit(AUDIT_LISTEN_NOT_VULN, 'Splunk', port);
}
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
