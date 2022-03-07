#############################################################################
#  yangxu
############################################################################
include("compat.inc");
if(description)
{
 script_id(51799186);
  script_category(ACT_ATTACK);
 script_family("CNDB");
 script_version("$Revision: 13 $");
 script_set_attribute(attribute:"last_modification", value:"$Date: 2016-02-22 11:23:30 +0000 (Mon, 22 Feb 2016) $");
 script_set_attribute(attribute:"creation_date", value:"2016-04-05 22:37:48 +0000 (Tue, 05 Apr 2016)");
 script_name(english:"kingbase DB Services detection");
 script_set_attribute(attribute:"description", value:"Detect the kingbase database is running");
 script_summary("Detect the kingbase database is running");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute : "solution" , value : "Service detection without modification");
 script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
 script_dependencies("find_service2.nasl","find_service1.nasl");
 script_require_ports("Services/unknown", 54321,54324);
 exit(0);
}

port = get_kb_item("Services/unknown");
if(!get_port_state(port)) exit(0);
if(get_port_state(port))
{
	peer0_0 = raw_string(0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f);
	peer0_1 = raw_string(
	0x00, 0x00, 0x00, 0x3a, 0x00, 0x03, 0x00, 0x03, 
	0x75, 0x73, 0x65, 0x72, 0x00, 0x53, 0x59, 0x53, 
	0x54, 0x45, 0x4d, 0x00, 0x64, 0x61, 0x74, 0x61, 
	0x62, 0x61, 0x73, 0x65, 0x00, 0x53, 0x41, 0x4d, 
	0x50, 0x4c, 0x45, 0x53, 0x00, 0x63, 0x6c, 0x69, 
	0x65, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x63, 0x6f, 
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x47, 0x42, 0x4b, 
	0x00, 0x00);
	peer0_2 = raw_string(
	0x70, 0x00, 0x00, 0x00, 0x28, 0x6d, 0x64, 0x35, 
	0x39, 0x31, 0x33, 0x37, 0x34, 0x34, 0x63, 0x33, 
	0x61, 0x34, 0x38, 0x62, 0x65, 0x65, 0x36, 0x34, 
	0x63, 0x66, 0x61, 0x36, 0x61, 0x61, 0x32, 0x65, 
	0x39, 0x37, 0x61, 0x31, 0x31, 0x65, 0x37, 0x39, 
	0x00);


	soc = open_sock_tcp(port);
	if(!soc){
	 exit(0);
	}
	send(socket:soc, data:peer0_0);
	buf = recv(socket:soc, length:5);
	send(socket:soc, data:peer0_1);
	send(socket:soc, data:peer0_2);
	buf2 = recv(socket:soc, length:1024);
	if(raw_string(0x4e)><buf && ('"SYSTEM"' >< buf2 || 'VFATAL' >< buf2))
	{
        vers1 = "Detect kingbase database";
        security_hole(port:port,data:vers1);
	}
	close(soc);
	exit(0);
}

if(get_port_state(port))
{
	peer0_0 = raw_string(
	0x4e, 0x76, 0x65, 0x72, 0x73, 
	0x69, 0x6f, 0x6e, 0x20, 0x30, 
	0x32, 0x30, 0x30);
	peer0_1 = raw_string(0x0d, 0x0a);
	peer0_2 = raw_string(
	0x41, 0x75, 0x73, 0x65, 0x72, 
	0x20, 0x53, 0x59, 0x53, 0x54, 
	0x45, 0x4d);
	peer0_3 = raw_string(0x0d, 0x0a);
	peer0_4 = raw_string(
	0x41, 0x70, 0x61, 0x73, 0x73, 
	0x20, 0x31, 0x32, 0x33, 0x34, 
	0x35, 0x36);
	peer0_5 = raw_string(0x0d, 0x0a);


	soc = open_sock_tcp(port);
	if(!soc){
	 exit(0);
	}
	send(socket:soc, data:peer0_0);
	send(socket:soc, data:peer0_1);
	buf = recv(socket:soc, length:5);
	send(socket:soc, data:peer0_2);
	send(socket:soc, data:peer0_3);
	send(socket:soc, data:peer0_4);
	send(socket:soc, data:peer0_5);
	buf2 = recv(socket:soc, length:100);
	if(raw_string(0x52)><buf && "failed" >< buf2)
	{
        vers1 = "Detect kingbase database";
        security_hole(port:port,data:vers1);
	}
	close(soc);
	exit(0);
}

exit(0);

