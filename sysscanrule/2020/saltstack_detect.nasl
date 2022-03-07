include("compat.inc");

if (description)
{
  script_id(51799243);
  script_version("1.3");
  script_cvs_date("Date: 2020/05/03");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_name(english:"saltstack services detect");
  script_summary(english:"saltstack services detect");
  script_set_attribute(attribute:"description", value:"saltstack services detect.");
  script_set_attribute(attribute:"solution", value:"No solution");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value: "2020/02/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_dependencies("find_service1.nasl","httpver.nasl");
  script_require_ports("Services/unknown", 4505, 4506);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

port = get_kb_item("Services/unknown");
if (!port) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


strreq1 = raw_string(0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f);

strreq2 = raw_string(0x03, 0x00, 0x4e, 0x55, 0x4c, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:strreq1);
send(socket:soc, data:strreq2);

res_1 = recv(socket:soc, length:20);
text = res_1[12]+res_1[13]+res_1[14]+res_1[15];
if (hexstr(res_1[0]) == "ff" && text == "NULL")
  {
    security_hole(port:port,data:"saltstack Servers Detect");
    set_kb_item(name:"Services/saltstack",value:port);
  }
close(soc);
exit(0);
