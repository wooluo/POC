#############################################################################
#yangxu
#############################################################################


include("compat.inc");
if(description)
{
 script_id(51799157);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_version("$Revision: 13 $");
 script_set_attribute(attribute:"last_modification", value:"$Date: 2016-02-22 11:23:30 +0000 (Mon, 22 Feb 2016) $");
 script_set_attribute(attribute:"creation_date", value:"2016-04-05 22:37:48 +0000 (Tue, 05 Apr 2016)");
 script_name(english:"Dameng DB Services detection");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"description", value:"Detect the dameng database is running");
 script_summary("Detect the dameng database is running");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
 script_set_attribute(attribute : "solution" , value : "Service detection without modification");
 script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
 script_dependencies("find_service2.nasl","find_service1.nasl");
 script_require_ports("Services/unknown", 5236, 5237);
 exit(0);
}

#port = 5236;

port = get_kb_item("Services/unknown");


if(get_port_state(port))
{
	req = raw_string( 
	0xff, 0xff, 0xff, 0xff, 0xc8, 0x00, 0x51, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x08, 0x00, 0x00, 0x00, 0x37, 0x2e, 0x37, 0x2e, 
	0x37, 0x2e, 0x37, 0x35, 0x00, 0x40, 0x00, 0x00, 
	0x00, 0xad, 0x9b, 0x59, 0x34, 0x84, 0x5e, 0x65, 
	0x4c, 0x08, 0x2b, 0x17, 0xbe, 0x33, 0x02, 0x5e, 
	0xab, 0xbc, 0xe4, 0x66, 0x80, 0x4d, 0x3a, 0x35, 
	0x30, 0x7a, 0x1c, 0x58, 0x9d, 0x16, 0xeb, 0x7f, 
	0xcc, 0x46, 0x6d, 0xf6, 0x95, 0x7a, 0x99, 0xab, 
	0x8b, 0x34, 0x8e, 0x43, 0x75, 0xf7, 0xb9, 0xf7, 
	0x39, 0x24, 0xd7, 0x15, 0xfd, 0x20, 0x9c, 0x31, 
	0x3c, 0x86, 0x6d, 0x75, 0x14, 0x44, 0xd6, 0x8f, 
	0xcd );
	soc = open_sock_tcp(port);
	if(!soc){
	 exit(0);
	}
	send(socket:soc, data:req);
	buf = recv(socket:soc, length:256);
	if(strlen(buf) < 100 && hexstr(buf[04]) != "e4")
	{
	  close(soc);
	  exit(0);
	}
	if(buf[91] == raw_string(0xff))
	{
		version = buf[84] + "." + buf[86] + "." + buf[88] + "." + buf[90];
	}
	if(buf[93] == raw_string(0xff) && buf[92] != raw_string(0xff))
	{
		version = buf[84] + "." + buf[86] + "." + buf[88] + "." + buf[90] + buf[91] + buf[92];
	}
	if(buf[93] == raw_string(0xff) && buf[92] == raw_string(0xff))
	{
	    version = buf[84] + "." + buf[86] + "." + buf[88] + "." + buf[90] + buf[91];
	}
	if (version && (buf[84] == 7 || buf[84] == 8))
	{report = "DM " + version;
    vers1 = "DM Database Version:"+version;
	set_kb_item(name:"dameng_version_"+port,value:version);
	set_kb_item(name:"dameng_port",value:port);
    security_hole(port:port,data:vers1);
	}
	}
