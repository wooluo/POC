#
# This script was written by John Lampe ... jwlampe@aceryder.com
# based on discussions with the guys from SPI Dynamics

if(description)
{
 script_id(50001);
 script_version ("$Revision: 1.0 $");
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

single_quote = raw_string(0x27);

poison[0] = single_quote + "UNION" + single_quote;
poison[1] = single_quote;
poison[2] = single_quote + "%22";
poison[3] = "9%2c+9%2c+9";
poison[4] = single_quote + "bad_bad_value";
poison[5] = "bad_bad_value" + single_quote;
poison[6] = single_quote + "+OR+" + single_quote;
poison[7] = single_quote + "WHERE";
poison[8] = "%3B"; 
poison[9] = single_quote + "OR";
poison[10] = single_quote + " or 1=1--";
poison[11] = " or 1=1--";
poison[12] = single_quote + " or " + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[13] = single_quote + ") or (" + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[14] = ";SELECT%20*";
poison[15] = "%20OR1=1";
poison[16] = "%20AND%201=1";
poison[17] = single_quote + "%20AND%20" + single_quote + "1" + single_quote + "=" + single_quote + "1";


posreply[0] = "Can't find record in";
posreply[1] = "Column count doesn't match value count at row";
posreply[2] = "error " + single_quote;
posreply[3] = "800A0409";
posreply[4] = "800A0CC1";
posreply[5] = "Invalid parameter type";
posreply[6] = "Microsoft OLE DB Provider for ODBC Drivers error";
posreply[7] = "ODBC Microsoft Access Driver";
posreply[8] = "ODBC SQL Server Driver";
posreply[9] = "supplied argument is not a valid MySQL result";
posreply[10] = "runtime error";
posreply[11] = "Unknown table";
posreply[12] = "You have an error in your SQL syntax";
posreply[13] = "Microsoft VBScript runtime";
posreply[14] = "Syntax";
posreply[15] = "80005000";
posreply[16] = "80020005";
posreply[17] = "800401E4";
posreply[18] = "80040E14";
posreply[19] = "80040E37";
posreply[20] = "80041010";
posreply[21] = "80071329";
posreply[22] = "8007203A";
posreply[23] = "800A000D";
posreply[24] = "800A01AD";
posreply[25] = "800A01C3";
posreply[26] = "800A01C2";
posreply[27] = "800A01F4";
posreply[28] = "800A01F5";
posreply[29] = "800A03EA";
posreply[30] = "800A03EE";
posreply[31] = "800A03F1";
posreply[32] = "800A03F2";
posreply[33] = "800A03FD";
posreply[34] = "800A0400";
posreply[35] = "800A0401";
posreply[36] = "800A0407";
posreply[37] = "800A0408";



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
fields[17] = "User-Agent: ";
fields[18] = "WWW-Authenticate: ";
fields[19] = "Keep-Alive: ";
fields[20] = "Age: ";
fields[21] = "Allow: ";
fields[22] = "Authorization: ";
fields[23] = "Cache-Control: ";
fields[24] = "Content-Length: ";
fields[25] = "Content-Location: ";
fields[26] = "Content-Type: ";
fields[27] = "Expires: ";
fields[28] = "From: ";
fields[29] = "If-Match: ";
fields[30] = "If-Modified-Since: ";
fields[31] = "If-None-Match: ";
fields[32] = "If-Range: ";
fields[33] = "If-Unmodified-Since: ";
fields[34] = "Last-Modified: ";
fields[35] = "Location: ";
fields[36] = "Max-Forwards: ";
fields[37] = "Pragma: ";
fields[38] = "Range: ";
fields[39] = "Retry-After: ";
fields[40] = "Server: ";
fields[41] = "TE: ";
fields[42] = "Trailer: ";
fields[43] = "Upgrade: ";
fields[44] = "Vary: ";
fields[45] = "Via: ";
fields[46] = "Warning: ";



# make sure this isn't some goofy web page of SQL error statements or something
soc = open_sock_tcp(port);
send (socket:soc, data:string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n"));
r = recv(socket:soc, length:4096);
close(soc);
for (i=0; posreply[i]; i++)
{
	if (posreply[i] >< r)
	{
		posreply[i] = string("W3", rand() ,"W0n7M4tch", rand(), "0nth1s");
		poscount++;
	}
}

if (poscount > 37)		#que demonios es eso?
	exit(0);




for (i=0; fields[i]; i += 4)
{
    for (j=0; poison[j] ; j++)
    {
	for (z=0; z<2; z++)
	{
		if ((z % 2) == 1)
		{
			upoison = myunicode(mydata:poison[j]);
			ratkiller = string(fields[i],upoison,"\r\n",fields[i+1],upoison,"\r\n",fields[i+2],upoison,"\r\n",fields[i+3],upoison);
		}
		else
		{
			ratkiller = string(fields[i],poison[j],"\r\n",fields[i+1],poison[j],"\r\n",fields[i+2],poison[j],"\r\n",fields[i+3],poison[j]);
		}
		req = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n", ratkiller , "\r\n\r\n");
		soc = open_sock_tcp(port);
		if (! soc)
		{
	    		if ( (i > 0) && (j > 0) )
	    		{
				mywarning = string("
The remote host is no longer responding to queries.
It is altogether possible that this check (SQL Header 
Injection) has caused the Webserver to stop responding.\n");
	    			security_hole(port);
	    		}
	    		exit(0);
		}
		send(socket:soc, data:req);
		r = recv(socket:soc, length:4096);
		close(soc);
		if (r)
		{
	    		for (mu=0; posreply[mu]; mu++)
	    		{
				if (posreply[mu] >< r)
				{
		    			mywarning = string("The remote host appears vulnerable to SQL injection via the following request:\n", req, "\n\n");
		    			mywarning += string("Response from Server was:\n", posreply[mu], "\n\n");
		    			security_hole(port:port, data:mywarning);
				}
	    		}
		}	
    	}
    }
}


