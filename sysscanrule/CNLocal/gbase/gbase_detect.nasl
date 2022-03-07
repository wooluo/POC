#############################################################################
# Author: shiyunshu
# Copyright @WebRAY
#############################################################################


include("compat.inc");
if(description)
{
	script_id(51799184);
	script_category(ACT_GATHER_INFO);
	script_family("CNDB");
	script_version("$Revision: 13 $");
	script_set_attribute(attribute:"last_modification", value:"$Date: 2020-02-07 10:19:23 +0800 (Fri, 07 Feb 2020) $");
	script_set_attribute(attribute:"creation_date", value:"2020-02-07 10:19:23 +0800 (Fri, 07 Feb 2020)");
	script_name(english:"Nandashentong DB Services detection");
	script_set_attribute(attribute:"description", value:"Detect the Nandatongyong database is running");
	script_summary("Detect the Nandashentong database is running");
	script_set_attribute(attribute:"risk_factor", value:"None");
	script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
	script_set_attribute(attribute : "solution" , value : "Service detection without modification");
	script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
	script_dependencies("find_service2.nasl","find_service1.nasl");
	script_require_ports("Services/unknown", 5258);
	exit(0);
}

port = get_kb_item("Services/unknown");

if(get_port_state(port))
{
	req = raw_string( 
	0x26,0x00,0x00,0x01,0x85,0xa6,0x13,0x00,
	0x00,0x00,0x00,0x01,0x21,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x72,0x6f,0x6f,0x74,
	0x00,0x00 );
	soc = open_sock_tcp(port);
	if(!soc){
		exit(0);
	}
	send(socket:soc, data:req);
	buf = recv(socket:soc, length:256);
	if(strlen(buf) < 4)
	{
		close(soc);
		exit(0);
	}
	if(buf[4] == raw_string(0x0a))
	{
		version = buf[5] + buf[6] + buf[7] + buf[8] + buf[9];
	}

	if (version && buf[5] == 8)
	{
		report = "Gbase " + version;
		vers1 = "Gbase Database Version:"+version;
		set_kb_item(name:"Gbase_version_"+port,value:version);
		set_kb_item(name:"Gbase_port",value:port);
		security_hole(port:port,data:vers1);
	}
}
