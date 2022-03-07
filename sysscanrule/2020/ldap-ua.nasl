############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799231);
 name = "LDAP - unauthorized access";
 script_name(name);
 script_category(ACT_GATHER_INFO);
 script_family(english:"Databases");
 script_dependencies("find_service.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");  
 script_set_attribute(attribute:"description", value:"LDAP unauthorized access");
 script_set_attribute(attribute:"solution", value:"Set the password with at least 8 digits, preferably including upper and lower case letters, numbers, special characters, etc.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/ldap", 389);
 exit(0);
}


#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/ldap");
if(!port)port = 389;
if(!get_port_state(port))exit(0);

req = raw_string(0x30,0x84,0x00,0x00,0x00,0x59,0x02,0x01,0x05,0x63,0x84,0x00,
                 0x00,0x00,0x50,0x04,0x13,0x64,0x63,0x3d,0x6f,0x70,0x65,0x6e,
                 0x76,0x61,0x73,0x64,0x63,0x2c,0x64,0x63,0x3d,0x6e,0x65,0x74,
                 0x0a,0x01,0x02,0x0a,0x01,0x00,0x02,0x01,0x00,0x02,0x01,0x00,
                 0x01,0x01,0x00,0xa3,0x84,0x00,0x00,0x00,0x13,0x04,0x0b,0x6f,
                 0x62,0x6a,0x65,0x63,0x74,0x43,0x6c,0x61,0x73,0x73,0x04,0x04,
                 0x75,0x73,0x65,0x72,0x30,0x84,0x00,0x00,0x00,0x0d,0x04,0x0b,
                 0x64,0x69,0x73,0x70,0x6c,0x61,0x79,0x4e,0x61,0x6d,0x65);  

soc = open_sock_tcp(port);
if(!soc)return NULL;
send(socket:soc, data:req);
buf = recv(socket:soc, length:4096);
if( buf == NULL )return NULL;
close(soc);
if( "Not bind/authenticate yet">< buf){
	  	if (report_verbosity > 0) security_hole(port:port, extra:buf);
			  else security_hole(port);
    }

exit(0);
