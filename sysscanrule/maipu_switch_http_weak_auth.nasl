include("compat.inc");

if (description)
{
  script_id(51799012);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2019/01/15 12:13:59 $");

  #script_cve_id("CVE-1999-0508");

  script_name(english:"Maipu Network Device Default Password");
  script_summary(english:"Maipu Network Device Default Password (admin)");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default administrator
account.");
  script_set_attribute(attribute:"description", value:
"The remote Maipu Switch accepts the default password 'admin' for
the web administration console.  This console provides read/write
access to the switch's configuration.  An attacker could take
advantage of this to reconfigure the switch and possibly re-route
traffic.");
  script_set_attribute(attribute:"solution", value:
"Change the password for this account.");
  script_set_attribute(attribute:"risk_factor", value: "High" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2019 WebRAY Inc.");
  script_family(english:"Misc.");

  script_dependencie("http_version.nasl");
  #script_exclude_keys("global_settings/supplied_logins_only");
  #script_require_ports(80, 8080);
  script_require_keys("Services/www");
  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_service(svc:'www', default:80, exit_on_fail:TRUE);

server_name = get_kb_item("www/"+port+"/server");
if (server_name != "Maipu-Webs") exit(0, "The web server name "+server_name+" is not Maipu-Webs");

banner = get_kb_item("www/banner/"+port);
var item1 = pregmatch(pattern:"^HTTP/1\.1 405 Access Denied", string:banner);
var item2 = pregmatch(pattern:"^HTTP/1\.1 401 Unauthorized", string:banner);
if (isnull(item1) && isnull(item2)) exit(0, "The web server banner does not contain HTTP/1\.1 405 Access Denied");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# HTTP auth = ":admin"
# req = string("GET / HTTP/1.0\r\nAuthorization: Basic OmFkbWlu\r\n\r\n");

# HTTP auth = "admin:admin"
req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");

# Both work, second is used to be RFC compliant.

send(socket:soc, data:req);
buf = http_recv(socket:soc);
close(soc);

if ('AUTHENID="YWRtaW46YWRtaW4="' >< buf) security_hole(port:port);
else exit(0, "The web server listening on port "+port+" is not affected.");
