# bigip_web_detect.nasl
#
# History:
#
# 1.00, 12/13/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title (9/1/09)
# - register_install() call added (05/30/2019)

include("compat.inc");

if (description)
    {
    script_id(51799267);
    script_version("1.11");

    script_name(english:"F5 BIG-IP Web Management Interface Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is a web management interface." );
 script_set_attribute(attribute:"description", value:
"An F5 BIG-IP web management interface is running on this port." );
 script_set_attribute(attribute:"see_also", value:"https://www.f5.com/products/big-ip-services" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port, possibly using bigpipe command
'httpd allow ....  For regular, non-management network ports, the
traffic can be also restricted with BIG-IP stateful packet filters." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
    script_summary(english:"Detects F5 BIG-IP web management interface");
    script_family(english:"Web Servers");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (C) 2008-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
    script_dependencies("http_version.nasl");
    script_require_ports("Services/www",443);
    exit(0);
    }


include("http_func.inc");
include("http_keepalive.inc");
include("openvas-https2.inc");
include("misc_func.inc");
include("global_settings.inc");
include("install_func.inc");



wport = get_kb_item("Services/www");
ssl = get_kb_list("SSL/Transport/"+wport);
if(!ssl) exit(0);

if (!get_tcp_port_state(wport)) exit(0, "Port "+port+" is closed.");
req = http_get(item:"/tmui/login.jsp",port:wport);
resp = https_req_get(port:wport, request:req);
if (!resp) exit(1, "The web server on port "+port+" failed to respond.");

if ( egrep(pattern:"<title>BIG-IP[^<]*</title>",string:resp,icase:TRUE) )
{
 replace_kb_item(name:"www/bigip",value:TRUE);
 replace_kb_item(name:"www/"+port+"/bigip",value:TRUE);
 replace_kb_item(name:"Services/www/"+port+"/embedded",value:TRUE);

register_install(
  app_name: "F5 BIG-IP web management",
  port: port,
  path: "bigip",
  webapp: TRUE,
  cpe:"cpe:/a:f5:big-ip_application_security_manager");

 security_note(port);
}
