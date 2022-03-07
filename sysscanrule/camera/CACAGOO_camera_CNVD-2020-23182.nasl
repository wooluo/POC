include("compat.inc");


if (description)
{
  script_id(51799278);
  script_cve_id("CVE-2020-9349");
  script_version("1.3");
  script_name(english:"CACAGOO camera  CVE-2020-9349");
  script_summary(english:"CACAGOO camera CVE-2020-9349");
  script_set_attribute(attribute:"description", value:"The CACAGOO Cloud Storage Intelligent Camera TV-288ZD-2MP with firmware 3.4.2.0919 allows access to the RTSP service without a password.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/rtsp", 554,8001);
  exit(0);
}


############################################
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("json.inc");


port = get_kb_item("Services/rstp");
if (!port) port = 554;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

ip = get_host_ip();
if (!ip) ip = "127.0.0.1";

req = 'DESCRIBE rtsp://'+ip+':'+port+' * RTSP/1.0\r\nCSeq: 7\r\nAuthorization: Basic YWRtaW46\r\n\r\n';
send(socket:soc, data:req);
r = http_recv3(socket:soc);
if("200 OK" >< r && "a=control:rtsp://" >< r && "RTP/AVP" >< r){
	security_hole(port:port, data:"CACAGOO CAMREA RTSP : " + r);
}
close(soc);
exit(0);
