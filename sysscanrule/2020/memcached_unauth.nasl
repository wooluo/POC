#############################################################################
#yangxu
############################################################################
include("compat.inc");
if(description)
{
 script_id(51799226);
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_version("$Revision: 13 $");
 script_set_attribute(attribute:"last_modification", value:"$Date: 2016-02-22 11:23:30 +0000 (Mon, 22 Feb 2016) $");
 script_set_attribute(attribute:"creation_date", value:"2016-04-05 22:37:48 +0000 (Tue, 05 Apr 2016)");
 script_name(english:"memcached unauthorized access vulnerability");
 script_set_attribute(attribute:"description", value:"memcached unauthorized access vulnerability");
 script_summary("memcached unauthorized access vulnerability");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
 script_set_attribute(attribute : "solution" , value : "Configure a firewall policy to allow only specified IPs to access port 2181.");
 script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
 script_dependencies("memcached_detect.nasl");
 script_require_ports("Services/memcached", 11211);
 exit(0);
}

port = get_kb_item("Services/memcached");

if(get_port_state(port))
{
	req = hex2raw(s:"73746174730d0a");
	soc = open_sock_tcp(port);
	if(!soc){
	 exit(0);
	}
	send(socket:soc, data:req);
	buf = recv(socket:soc, length:10000);
	if(strlen(buf) < 50)
	{
	  close(soc);
          exit(0);
	}
	if ("STAT version" >< buf && "STAT pid" >< buf)
	{
              security_hole(port:port,data:buf);
	}
	close(soc);
	}
