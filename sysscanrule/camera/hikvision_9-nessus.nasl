############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799102);
  script_version("1.3");
  script_name(english:"Hikvision weak passwd vulnerability");
  script_summary(english:"Hikvision weak passwd vulnerability");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"Hikvision weak passwd vulnerability");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"vuln_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www", 80);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
	url = string("/PSIA/System/deviceInfo");
	passwds = make_list("Basic YWRtaW46MTIzNDU=","Basic YWRtaW46ODg4ODg4","Basic YWRtaW46MTIzNDU2","Basic YWRtaW46MTExMTEx","Basic YWRtaW46YWRtaW4=","Basic YWRtaW46d2VicmV5NjAz");
	foreach passwd (passwds){
          req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("X-Requested-With", "XMLHttpRequest","User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Authorization",passwd ));
	      if("200 OK">< req[0] && "</deviceID>" >< req[2] && "</macAddress>" >< req[2] && "</firmwareReleasedDate>" >< req[2]){
		      if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+req[2]);
			  else security_hole(port);
        }
	}
}

function check_vuln_ssl(port){
	url = string("/PSIA/System/deviceInfo");
	passwds = make_list("Basic YWRtaW46MTIzNDU=","Basic YWRtaW46ODg4ODg4","Basic YWRtaW46MTIzNDU2","Basic YWRtaW46MTExMTEx","Basic YWRtaW46YWRtaW4=","Basic YWRtaW46d2VicmV5NjAz");
	foreach passwd (passwds){
	    res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("X-Requested-With", "XMLHttpRequest","User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Authorization",passwd ));
		req = http_last_sent_request();
		ssl_req = https_req_get(port:port , request:req);
		if("200 OK"><ssl_req && "</deviceID>" >< ssl_req && "</macAddress>" >< ssl_req && "</firmwareReleasedDate>" >< ssl_req){
		    if (report_verbosity > 0) security_hole(port:port, extra:req+ssl_req);
			  else security_hole(port);
	    }

	}
}


##################################
kbs = get_kb_list("www/banner/*");
foreach k (keys(kbs)) {
	port = substr(k,11);
	ssl = get_kb_list("SSL/Transport/"+port);
	if(!ssl) {
   		check_vuln(port:port);
	} else {
   		check_vuln_ssl(port:port);
	}
}