#
# This script was written by John Lampe ... jwlampe@aceryder.com
# based on discussions with the guys from SPI Dynamics

if(description)
{
 script_id(11139);
 script_version ("$Revision:$");
 name["english"] = "SQL injection via HTTP headers";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to use SQL injection techniques on HTTP servers.
That is, many web sites will log certain 'header' information back to
a SQL server.  So, while many administrators and programmers may go to
great lengths to sanitize form data or request data, they may still be
vulnerable to an attack via HTTP headers.  

Note: This script is based on discussions with the guys from SPI Labs 

Solution : Modify the software to sanitize header values.

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "SQL injection via HTTP headers";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#





include("http_func.inc");


function myunicode(mydata)
{
	for (zeta=0; zeta < strlen(mydata); zeta++)
	{
		tstr2 = ereg_replace(string:hex(ord(mydata[zeta])), pattern:"0x([a-fA-F0-9]{2})", replace:"\1", icase:TRUE);
		tstring += string("%",tstr2);
	}
	return(tstring);
}



	
port = get_http_port(default:80);

if(! get_port_state(port))
        exit(0);

fields[0] = "Accept: ";
fields[1] = "Accept-Charset: ";
fields[2] = "Accept-Encoding: ";
fields[3] = "Accept-Language: ";
fields[4] = "Accept-Ranges: ";
fields[5] = "Connection: ";
fields[6] = "Content-Encoding: ";
fields[7] = "Content-Language: ";
fields[8] = "Content-MD5: ";
fields[9] = "Content-Range: ";
fields[10] = "Date: ";
fields[11] = "ETag: ";
fields[12] = "Expect: ";
fields[13] = "Host: ";
fields[14] = "Proxy-Authenticate: ";
fields[15] = "Proxy-Authorization: ";
fields[16] = "Referer: ";
fields[17] = "Transfer-Encoding: ";
fields[18] = "User-Agent: ";
fields[19] = "WWW-Authenticate: ";



soc = open_sock_tcp(port);
if (! soc)
	exit(0);

start = "GET / HTTP/1.0\r\n";
for (MAX=1; MAX < 4096; MAX++)
{
	start = "GET / HTTP/1.0\r\n";
	soc = open_sock_tcp(port);
	if (! soc)
	{
		if (MAX > 1) 
			display(string("MAX IS ", MAX, "\n"));
	}
	for (i=0; i<MAX ; i++)
	{
		curr = fields[i % 20];
		start += curr;
		for (z=0; z<256; z++)
		{
			start += raw_string(rand() % 256);
		}
		start += string("\r\n");
	}

	send(socket:soc, data:start);
	close(soc);
	#r = recv(socket:soc, length:65536);
	#display(r);
}	
