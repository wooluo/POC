#TRUSTED 8f10877d6a613b42ab52e8c95f1fd277546d09450be39027e1fc8df6ec6afeaa8bbbb632fc8cdb9f6f56f42ab218fb8bf145bde11fa3cd7f485cde7d0483776a12d63140335741557539f95e3c682ecb32b1a730de28f0cf4a7273cae99261fe28125dbcd0d6335c94008f98e36f5134c7e06df59b394f5699e7590afed812672edf0ef1c38531130869b8f990183a2b95b06d48bf04b164b0f11111d532f0a5c55280d5c38d6a54d7b825f5a851b462b7aae40777874d89062f375af6330285940daad36d2575cb6d96f71eb914bb475bb62e31d2090f3ff2e7a97f8affb34005e3cdc6631b7e8d3e703d825b250662e17b9fb7833ab58fef3dc19b56e27e92650aafcde5056044562120c5e447443581f99f8cec1abc0cf5cecf5660d98351c99508a340b909e6d99a984c3a51b5f5e1035402edd78efcb8f04dced8b46502b6d326d5a170393d134caae2c67df81024b405439eddca71efa7f7b8250a4d6b0ee35aa27abe66adac6f374dcd48384d055d9264f412ac94858e5c71ddf11c047fd3ba988b9f4ca46ed12cedbfe9dcaa9930579e3fbd8e0278ba9befd4312ee1a718bfe325879469a20e4af670e66aaafb067067ff43eaa390301df81e7e68b80f3e59b4053291c72c18f0d75ff5ea409807ef1d23df30e5d1db3ba678189ce0f396e5d1661b1c3b9a2d74985fd6fcaec23dca68b4990ef95d8de6c3450e7568
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# smtp_func.inc
# Revision: 1.39

include("compat_shared.inc");


global_var TAP_MODE = FALSE;

function smtp_close(socket)
{
  send(socket: socket, data: 'QUIT\r\n');
  smtp_recv_line(socket: socket);
  if (TAP_MODE) return NULL;
  return close(socket);
}

##
# returns NULL on failure, socket descriptor on success
##
function smtp_open(port, helo, exit_on_fail, ehlo, socket)
{
  local_var	data, greet, soc = socket, i=0;
 
  if (!isnull(helo) && !isnull(ehlo))
  {
    exit(1, "Error: smtp_open() called with both 'helo' and 'ehlo' parameters.");
  }

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (isnull(soc)) soc = open_sock_tcp(port);

  if (! soc)
  {
    if (exit_on_fail) exit(0, "Can't open a socket on port "+port+".");
    else return NULL;
  }

  data = smtp_recv_banner(socket:soc);
  if (! data)
  {
    smtp_close(socket: soc);
    if (exit_on_fail) exit(1, "Failed to receive the SMTP banner from the service listening on port "+port+".");
    else return NULL;
  }
  
  if (!isnull(helo))      { greet = 'HELO ' + helo + '\r\n'; }
  else if (!isnull(ehlo)) { greet = 'EHLO ' + ehlo + '\r\n'; }
  else                    { greet = NULL; }
  
  if ( isnull(greet) ) return soc;

  send(socket:soc, data: greet);
  data = smtp_recv_line(socket: soc);
  if(! preg(pattern:"^[2-3][0-9][0-9]", string:data))
  {
    var hs, h;
    smtp_close(socket: soc);
    hs = split(greet);
    if (!isnull(hs)) h = hs[0]; # redundant, but keeps pedant2 happy
    if (exit_on_fail) 
      exit(1, "The SMTP server listening on port "+port+" did not accept our "+h+".");
    else return NULL;
  }

  return soc;  
}

function smtp_send_socket(socket, from, to, body)
{
  local_var buff;
  # Just to be sure
  send(socket: socket, data: 'RSET\r\n');
  buff = recv_line(socket: socket, length: 2048);
  # Here, we might test the return code
  if (from !~ ' *<.*> *') from = '<' + from + '>';
  send(socket: socket, data: 'MAIL FROM: ' + from + '\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^2[0-9][0-9][ -]", string:buff)) { return (0); }
  
  if (to !~ ' *<.*> *') to = '<' + to + '>';
  send(socket: socket, data: 'RCPT TO: ' + to + '\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^2[0-9][0-9][ -]", string:buff)) { return (0); }

  send(socket: socket, data: 'DATA\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^3[0-9][0-9][ -]", string:buff)) { return (0); }

  # Make sure that every line ends up with \r\n
  # This is not useful yet, as only two scripts send data to the SMTP server
  #body = ereg_replace(string: body, pattern: string("([^\r])\n"), replace: string("\\1\r\n"));
  send(socket: socket, data: body);
  send(socket: socket, data: '\r\n.\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^2[0-9][0-9][ -]", string:buff)) { return (0); }
  return(1);
}

function smtp_send_port(port, from, to, body)
{
  local_var s, buff, ret, hostname;
  s = open_sock_tcp(port);
  if (! s) return (0);

  buff = recv_line(socket: s, length: 2048);
  if (strlen(buff) == 0 || buff !~ '^[1-5][0-9][0-9][ -]')
  {
    smtp_close(socket:s);
    return 0;
  }
  hostname = get_kb_item('smtp/'+ port + '/helo');
  if (! hostname) hostname = 'GizaNE';
  send(socket: s, data: 'HELO ' + hostname + '\r\n');
  buff = recv_line(socket: s, length: 2048);
  if (strlen(buff) == 0 || buff !~ '^[1-5][0-9][0-9][ -]')
  {
    smtp_close(socket:s);
    return 0;
  }
  # We should test the code
  ret = smtp_send_socket(socket: s, from: from, to: to, body: body);
  send(socket: s, data: 'QUIT\r\n');
  smtp_close(socket:s);
  return (ret);
}

function smtp_from_header()
{
 local_var fromaddr;
 fromaddr = get_kb_item("SMTP/headers/From");
 if (!fromaddr) fromaddr = "GizaNE@example.com";
 return (fromaddr);
}

function smtp_to_header()
{
 local_var toaddr;
 toaddr = get_kb_item("SMTP/headers/To");
 if (!toaddr) toaddr = 'postmaster@[' + get_host_ip() + ']';
 return (toaddr);
}

function get_smtp_banner(port, exit_on_fail)
{
  local_var sb, banner, to, soc;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  sb = 'smtp/banner/' + port;
  banner = get_kb_item(sb);
  if (banner) return (banner);
  if ( get_kb_item("smtp/" + port + "/broken") ) 
  {
    if (exit_on_fail) exit(1, "The SMTP server listening on port "+port+" is broken.");
    else return NULL;
  }

  if (!get_port_state(port)) 
  {
    if (exit_on_fail) exit(0, "Port "+port+" is not open.");
    else return (0);
  }
  soc = open_sock_tcp(port);
  if (! soc)
  {
    set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
    if (exit_on_fail) exit(0, "Can't open a socket on port "+port+".");
    else return NULL;
  }

  # nb: we'll handle failures here.
  banner = smtp_recv_banner(socket:soc, exit_on_fail:FALSE);
  smtp_close(socket:soc);
  if (!banner)
  {
    set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
    if (exit_on_fail) exit(1, "The SMTP server listening on port "+port+" did not return a banner.");
    else return NULL;
  }

  replace_kb_item(name: sb, value: banner);
  return(banner);
}


function smtp_recv_line(socket, code, retry, last)
{
 local_var ret, n, r, pat;
 
 if (isnull(code))
   pat = "^[0-9][0-9][0-9]-";
 else
   pat = "^" + code + "-";

 ret = "";
 r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 while (! r && n ++ < retry)
   r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 ret = r;
 if(strlen(r) < 4) 
  return r;
  
 while(preg(pattern: pat, string:r))
 {
  n = n + 1;
  r = recv_line(socket:socket, length:4096);
  if (strlen(r) == 0) break;
  if (n > 512)
   return NULL;
  if (last) ret = r;
  else      ret = ret + r;
 }
 return ret;
}

function smtp_recv_banner(socket, exit_on_fail)
{
  local_var b, oto, port, to;

  oto = NULL;
  if (defined_func("get_peer_name") && socket)
  {
    port = get_peer_name(socket);
    if (port) 
    {
      # nb: greetpause can NULL (missing), 0, or > 0.
      to = get_kb_item("smtp/"+port[1]+"/greetpause");
      if (isnull(to)) to = 30;
      if (to) oto = socket_set_timeout(socket:socket, timeout:to);
    }
  }

  b = smtp_recv_line(socket:socket, code:"220");
  if (!isnull(oto)) socket_set_timeout(socket:socket, timeout:oto);

  if (strlen(b) == 0 && exit_on_fail)
  {
    if (port) exit(1, "Failed to retrieve the banner from the SMTP server listening on port "+ port[1] +".");
    else exit(1, "Failed to retrieve the SMTP server's banner.");
  }
  return b;
}


#----------------------------------------------------------------#
# Function    : smtp_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'dont_read_banner' => read the initial service   #
#                 banner unless set to TRUE. (optional)          #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
#               'exit_on_fail' => if specified, exit on a        #
#                 failure rather than returning NULL.            #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (smtp_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function smtp_starttls(socket, dont_read_banner, encaps, exit_on_fail, use_ehlo)
{
  var data;
  var greet; 

  if (use_ehlo) greet = 'EHLO';
  else greet = 'HELO';

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (!dont_read_banner)
  {
    data = smtp_recv_banner(socket:socket);
    if (!data)
    {
      if (exit_on_fail) exit(1, "Failed to get the banner from the SMTP server.");
      else return NULL;
    }
    
    # Send the HELO/EHLO message
    send(socket:socket, data:greet+' '+compat::this_host()+'\r\n');
    data = smtp_recv_line(socket:socket);
    if(!preg(pattern:"^[2-3][0-9][0-9]", string:data))
    if (!data)
    {
      if (exit_on_fail) exit(1, "The SMTP server did not accept our "+greet+".");
      else return NULL;
    }
  }

  send(socket:socket, data:'STARTTLS\r\n');
  data = smtp_recv_line(socket:socket, retry:5);
  if (strlen(data) < 4) 
  {
    if (exit_on_fail) exit(1, "The SMTP server did not send back a valid response to a STARTTLS command.");
    else return NULL;
  }

  if (substr(data, 0, 2) != "220") return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) 
    {
      if (exit_on_fail) exit(1, "Failed to negotiate an SSL / TLS connection after sending a STARTTLS command.");
      else return NULL;
    }
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}

function smtp_send_raw (socket, data)
{
  var n = strlen(data);
  if (substr(data, n-2) != '\r\n') data += '\r\n';
  return send(socket:socket, data:data);
}
  
