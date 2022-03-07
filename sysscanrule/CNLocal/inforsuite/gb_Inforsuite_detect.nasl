#############################################################################
#yangxu
#############################################################################


include("compat.inc");
if(description)
{
 script_id(51799188);
 script_category(ACT_GATHER_INFO);
 script_family("CNLocal");
 script_version("$Revision: 13 $");
 script_set_attribute(attribute:"last_modification", value:"$Date: 2016-02-22 11:23:30 +0000 (Mon, 22 Feb 2016) $");
 script_set_attribute(attribute:"creation_date", value:"2016-04-05 22:37:48 +0000 (Tue, 05 Apr 2016)");
 script_name(english:"Inforsuite Middleware Services detection");
 script_set_attribute(attribute:"description", value:"Detect the Inforsuite Middleware is running");
 script_summary("Detect the Inforsuite Middleware is running");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute: "solution" , value: "Service detection without modification");
 script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
 script_dependencies("find_service2.nasl","find_service1.nasl");
 script_require_ports("Services/www", 80,8060);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/www");

if(get_port_state(port))
{
    req = http_send_recv3(method: "GET", host:get_host_ip(),item:"/", port:port);
	if("Server:" >!< req[1]) exit();
	if ("Server:" >< req[1] && ("InforSuite APP Server" >< req[1] || "Server: Inforsuite Application Server" >< req[1])){
	    item = eregmatch(pattern:"Server: InforSuite APP Server ([0-9.]+)", string:req[1]);
            if (strlen(item[1]) > 2){
                fix = split(item[1], sep:'.', keep:FALSE);
                if (fix[0]<= 9)
                {
                  security_hole(port:port,data:item[0]);
                  exit();
                }
            } 
	    security_hole(port:port);
	}
	
}