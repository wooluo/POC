
##
# 
##


include('compat.inc');

if (description)
{
  script_id(150056);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/28");

  script_cve_id("CVE-2021-3273");
  script_xref(name:"IAVB", value:"2021-B-0030");

  script_name(english:"Nagios XI < 5.7 Code Injection");
  script_set_attribute(attribute:"synopsis", value:"The remote host has a web application affected by a code injection vulnerability.");
  script_set_attribute(attribute:"description",value:
"Nagios XI below 5.7 is affected by code injection in the /nagiosxi/admin/graphtemplates.php component. To exploit this
vulnerability, someone must have an admin user account in Nagios XI's web system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:"Upgrade Nagios XI 5.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3273");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl");
  script_require_keys("installed_sw/nagios_xi");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http_func.inc');
include('webapp_func.inc');
include('spad_log_func.inc');

# Get the ports that web servers have been found on.
var port = get_http_port(default:80);

# Get details of the install.
var install = get_install_from_kb(appname:'nagios_xi', port:port, exit_on_fail:TRUE);
spad_log(message:'install: ' + obj_rep(install));
var dir = install['dir'];
var ver = install['ver'];
var url = build_url(port:port, qs:dir + '/');

if (ver == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Nagios XI', url);

var matches = pregmatch(string:ver, pattern:"^((\d+)R([.\d]+)|[0-9.]+)");
if (empty_or_null(matches))
  exit(1, 'Unable to parse version string for Nagios server on port ' + port + '.');

var vuln = FALSE;
if (ver =~ "^20\d\d")
  vuln = TRUE;

var modern_ver_match = pregmatch(string:ver, pattern:"^([0-9.]+)");
if (!empty_or_null(modern_ver_match))
{
  modern_ver_match = modern_ver_match[1];
  if (ver_compare(fix:'5.7.0', ver:modern_ver_match) < 0)
    vuln = TRUE;
}

if (!vuln)
  audit(AUDIT_INST_VER_NOT_VULN, 'Nagios XI', ver);

report =
  '\n  URL               : ' + url +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : 5.7.0' +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
