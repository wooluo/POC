#
# (C) WebRAY, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109553);
  script_version("1.1");
  script_cvs_date("Date: 2018/05/03 19:07:47");

  script_name(english:"Oracle WebLogic HTTP Detection");
  script_summary(english:"Checks for presence of Oracle WebLogic HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"Oracle WebLogic HTTP server is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Oracle (formerly BEA) WebLogic, a Java EE application server, is
running on the remote web server.");
  # http://www.oracle.com/technetwork/middleware/weblogic/overview/index.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by WebRAY, Inc.");

  script_require_ports("Services/www", 80, 7001, 7002, 9002);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc"); 

appname = "WebLogic";

port = get_http_port(default: 7001);
banner = get_http_banner(port: port);
if (empty_or_null(banner))
{
  audit(AUDIT_NO_BANNER, port);
}

function parse_cr_patches(server_string) 
{
  local_var cr_list;
  local_var cur_cr;
  local_var parsing_cr;
  local_var i;
  local_var cur_char;

  cr_list = make_list();
  parsing_cr = FALSE;
  cur_cr = '';

  for(i=0; i<strlen(server_string); i++) 
  {
    if (parsing_cr) 
    {
      cur_char = substr(server_string, i, i);
      if (cur_char == ' ' || cur_char == ',')
      {
        cr_list = make_list(cr_list, cur_cr);
        parsing_cr = FALSE;
      }
      else
      {
         if (cur_char =~ "[CR0-9]")
           cur_cr += cur_char;
         else parsing_cr = FALSE;
      }
    }
    else 
    {
      if (substr(server_string, i, i+3) =~ " CR[0-9]") {
        cur_cr = '';
        parsing_cr = TRUE;
      }
    }
  }

  return cr_list;
}

# Parses the old version of the Weblogic HTTP server field.
# Example server strings in header:
# Server: WebLogic Server 9.2 Fri Jun 23 20:47:26 EDT 2006 783464
# Server: WebLogic WebLogic Server 7.0 SP2  Sun Jan 26 23:09:32 PST 2003 234192
# Server: WebLogic Server 8.1 Temporary Patch for CR335437, CR341097 Wed Sep 05 17:29:52 PDT 2007
# Server: WebLogic Server 9.2 MP2 Mon Jun 25 01:32:01 EDT 2007 952826
# Server: WebLogic Server 10.0 MP1 Thu Oct 18 20:17:44 EDT 2007 1005184
# @param server_name the server field from the HTTP header
# @return a string describing the server if found
function old_style_banner(server_name)
{
  var info = 'URL : ' + build_url(port:port, qs:"/") + '\n';
  replace_kb_item(name:"www/weblogic/" + port + "/source", value: server_name);

  var pattern = "^Server:.*WebLogic Server ([0-9]+\.[0-9]+)[0-9\.]*( SP[0-9]+ | MP[0-9]+ )?";
  var item = pregmatch(pattern: pattern, string: server_name);
  if (isnull(item)) audit(AUDIT_RESP_BAD, port);

  var version_number = item[1];
  info += 'Version : ' + version_number + '\n';
  replace_kb_item(name:"www/weblogic/" + port + "/version", value:version_number);

  if (max_index(item) > 2)
  {
    var service_pack = ereg_replace(pattern:" (SP[0-9]+|MP[0-9]+) ", replace:"\1", string:item[2]);
    replace_kb_item(name:"www/weblogic/" + port + "/service_pack", value:service_pack);
    info += 'Service / Maintenance Pack : ' + service_pack + '\n';
  }

  # Parse any critical patches that have been applied
  var patches = parse_cr_patches(server_string:server_name);
  if (max_index(patches) > 0) info += 'Critical patches applied : \n';

  var patch;
  foreach patch (patches)
  {
    set_kb_item(name:"www/weblogic/" + port + "/cr_patches/" + patch, value:TRUE);
    info += '  ' + patch + '\n';
  }
  return info;
}

# Tries to connect to the web admin login to determine if the server
# is WebLogic.
# @return a string describing the server if found
function get_web_console()
{
  var url = "/console/login/LoginForm.jsp";
  var res = http_send_recv3(method: "GET", port:port, item:"/console/login/LoginForm.jsp", follow_redirect: 1, exit_on_fail:TRUE);
  if (empty_or_null(res))
  {
    audit(AUDIT_RESP_NOT, port, "the login form request");
  }

  if (res[0] =~ '^HTTP/[0-9.]+ +200' && preg(string:res[2], pattern:"<title>(Oracle|BEA) WebLogic Server", icase:TRUE, multiline:TRUE))
  {
    # attempt to get the version from the login page (not availabe for BEA)
    var matches = pregmatch(pattern: "WebLogic Server Version: *([0-9.]+)", string: res[2]);
    if (!empty_or_null(matches))
    {
      var info = '\nURL     : ' + build_url(port:port, qs:url) +
                 '\nVersion : ' + matches[1] +
                 '\n';
      replace_kb_item(name:"www/weblogic/" + port + "/version", value:matches[1]);
      return info;
    }
  }
  return NULL;
}

info = '';
server_name = pgrep(pattern: "^Server:.*WebLogic.*", string: banner);
if (server_name)
{
  if (server_name =~ "^WL-Result:.*UNAVAIL.*")
  {
    info +=
      '\n' + 'While the remote server can be fingerprinted as WebLogic, the service' +
      '\n' + 'is currently unavailable, probably because of a connection limit with' +
      '\n' + 'licensing.\n';
  }
  else
  {
    info = old_style_banner(server_name: server_name);
  }
}
else
{
  info = get_web_console();
}

if (empty_or_null(info))
{
  audit(AUDIT_NOT_INST, appname);
}

set_kb_item(name:"www/weblogic", value: TRUE);
set_kb_item(name:"www/weblogic/ports", value:port);
set_kb_item(name:"www/weblogic/" + port + "/installed", value: TRUE);
security_report_v4(severity:SECURITY_NOTE, port:port, extra:info);
