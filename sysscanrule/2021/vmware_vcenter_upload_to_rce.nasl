include("compat.inc");


if (description)
{
  script_id(51799307);
  script_version("1.3");
  script_name(english:"Vmware Vcenter any file upload");
  script_summary(english:"Vmware Vcenter any file upload");
  script_set_attribute(attribute:"description", value:"Vmware Vcenter any file upload.");
  script_set_attribute(attribute:"solution", value:"Vmware Vcenter any file upload");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("vmware_vcenter_detect.nbin");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Host/VMware/vCenter");
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");
include("install_func.inc");
include("dump.inc");

port = get_kb_item("Host/VMware/vCenter");
soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port, appname);
}
if (get_kb_list("SSL/Transport/"+port)){
	req = http_post(item:"/ui/vropspluginui/rest/services/uploadova", port:port, data:"uploadFile=test.tar");
	ssl_reqs = https_req_get(request:req, port:port);
	if("VSPHERE-UI" >< ssl_reqs && "Required CommonsMultipartFile parameter 'uploadFile' is not present" >< ssl_reqs){
		security_hole(port:port, extra:"Vmware vcenter Upload To RCE");
	}
	else{
		res = http_get(item:"/ui/vropspluginui/rest/services/getstatus", port:port);
		ssl_ress = https_req_get(request:res, port:port);
		if("200 OK" >< ssl_ress && '"Install Progress"' >< ssl_ress){
			security_hole(port:port, extra:"Vmware vcenter Upload To RCE");
		}
	
	}
	
}
close(soc);