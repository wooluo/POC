#TRUSTED 35454fc7ab01d07597e2558a201dfc39dce60286f2b61045a060e07e578de61d1b19e9a982a586ea15e75a115ef06bbc556d336feb89e843f5f49c1edf5fddd36a60fbca1c0ce4c0b60f17cfd68cf6768a7ffa4d011c9fd847a5f1789510124172e36d08249f29521cf910e4db08ecbf9cf841b239c3ddf5da32a2a9dd1f543865810eb8295d17cdde87898d8fb1773b1a563a58de72f3a65d7bb022d5f2f250d1a911df813dc59f67dc8828edc62add0fd29d2b848407da2d6dd22b5a81442c665828b2eb5d7a6234bc970658e75c423c8ca9d07c90a18277c7d2e338168c6be51e27c0950ee14ccad7dc4ed3f46d497b1e7c511712d5067310075ac22d3769a5044e37f7d5575e7fc37bd7f309d3dffb63d627bfca0ede8c0d8bf70ab3e477d2dbe251c3f316f3537492af982b6683d1855fd780acc3de84cde29f0b90e8b72c614f4a27e41615ca48dad6fa4e624eaddc02ac3a343a2315b9729989296d78520116199767fe3b622fb53b025182aa707bf438320c24e0db4fc77e6daefe00e3333e44d82aee9d6a271d2b54ff71151e3d5febeaa8e76eb8aff0744349cc8433d90b3bcde2eed7e14618d6ba437d6cd70ad66e48db048893b6bd3368815799896c5b681710dea014c782c65f3b4b2d07c009d92055f1775585131503d81d9309135b46ddee8f5b66e5da3747ec4c0d4ef2885a51ef44b3a654ae50facdd40e
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# misc_func.inc
#
# Revision: 1.161
#

# global_settings.inc must be separately included by any plugins including misc_func.inc

global_var _branch_identifier;
_branch_identifier = 0;

# OT KB entries are Known/otproto/<a protocol> when known / detected
global_var KB_OT_PROTO = "Known/otproto";

function register_service(port, proto, ipproto, otproto)
{
  local_var	k;

  if (! ipproto) ipproto = "tcp";

  port = int(port);
  if ( port <= 0 || port > 65535 ) return;

  if (! service_is_unknown(port:port, ipproto: ipproto))
  {
    if (debug_level) display(get_host_ip(), ": service is already known on port ", ipproto, ":", port, "\n");
    #return(0);
  }

  if ( proto != "unknown" )
  {
   k = "Known/" + ipproto + "/" + port;
   replace_kb_item(name: k, value: proto);
   if (ipproto == "tcp") k = "Services/" + proto;
   else k = "Services/" + ipproto + "/" + proto;
   set_kb_item(name: k, value: port);
   if ( !isnull(otproto) )
   {
    set_kb_item(name: KB_OT_PROTO + "/" + proto, value: otproto);
   }
  }
  if ( ipproto == "tcp" )
    rm_kb_item(name:"Services/unknown", value:port);

   if (debug_level) display(get_host_ip(), ": register_service: port=", port, ", proto=", proto, "\n");
}

# This function may fork!
function known_service(port, ipproto)
{
  local_var	k, p;
  if (! ipproto) ipproto = "tcp";
  k = "Known/" + ipproto + "/" + port;
  p = get_kb_item(k);
  #if (p) { display("Known service on port ", port, "\n"); }
  #else { display("Unknown service on port ", port, "\n"); }
  return p;
}

function silent_service()
{
 local_var port;

 port = _FCT_ANON_ARGS[0];
 if ( get_kb_item("Services/Silent/" + port) ) return TRUE;
 else return FALSE;
}

# This function does not fork!
function service_is_unknown(port, ipproto)
{
  local_var	k, p;
  if (! ipproto) ipproto = "tcp";
  k = "Known/" + ipproto + "/" + port;
  p = get_kb_list(k);
  if (isnull(p)) return TRUE;
  foreach k (p)
    if (k != "unknown")	# fool proof
      return FALSE;
  return TRUE;
}

function scratchpad_tables_exist(tables)
{
  local_var table;

  if(isnull(tables))
  {
    if(!isnull(_FCT_ANON_ARGS[0]))
      tables = _FCT_ANON_ARGS[0];
    else
      return FALSE;
  }
  foreach table (tables)
  {
    if(!scratchpad_table_exists(table:table))
      return FALSE;
  }

  return TRUE;
}


function scratchpad_table_exists(table)
{
  local_var ret;

  if(isnull(table))
  {
    if(!isnull(_FCT_ANON_ARGS[0]))
      table = _FCT_ANON_ARGS[0];
    else
      return FALSE;
  }

  ret = query_scratchpad(
    "SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table'" +
    " AND name=?", table);
  if(isnull(ret) || ret[0]["cnt"] == 0) 
    return FALSE;

  return TRUE;
}

function verify_service(port, ipproto, proto)
{
  local_var	k, p;
  # Remember: no KB yet in command line mode!
  if (! ipproto) ipproto = "tcp";
  k = "Known/" + ipproto + "/" + port;
  p = get_kb_list(k);
  foreach k (p)
    if (k == proto)
      return TRUE;
  return FALSE;
}

#----------------------------------------------------------------#
# Function    : get_service                                      #
# Description : Returns a port number for a given IP protocol.   #
# Inputs      : 'ipproto' => an IP protocol. (optional)          #
#               'svc' => a service name. (required)              #
#               'default' => fall-back port number. (optional)   #
#               'exit_on_fail' => exit on a failure. (optional)  #
# Return      : A port number or 0 if none exists.               #
# Notes       : The function calls exit() if no port was found   #
#                 or it is not open and 'exit_on_fail'           #
#                 evaluates as TRUE.                             #
#               This function may fork.                          #
# Usage       : port = get_service(svc:"smtp", default:25);      #
#----------------------------------------------------------------#
function get_service(svc, ipproto, default, exit_on_fail)
{
  local_var a, p, c;

  if (!svc) return 0;

  c = 1;
  if (!ipproto || ipproto == "tcp")
    p = get_kb_item("Services/"+svc);
  else
    p = get_kb_item("Services/"+ipproto+"/"+svc);

  if (!p)
  {
    if (default && service_is_unknown(port:default, ipproto: ipproto))
    {
     p = default;
     c = 0;
    }
    else
    {
      if (exit_on_fail)
      {
        a = "No '" + svc + "' service was detected";
        if (default)
        {
          if (!ipproto) a = a + ", including on TCP port " + default;
          else a = a + ", including on " + toupper(ipproto) + " port " + default;
        }
        a = a + ".";
        exit(0, a);
      }
    }
  }
  if (exit_on_fail)
  {
    if (!ipproto || ipproto == "tcp")
    {
      if (!get_tcp_port_state(p)) exit(c, "Port "+p+" is not open.");
    }
    else if (ipproto && ipproto == "udp")
    {
      if (!get_udp_port_state(p)) exit(c, "UDP port "+p+" is not open.");
    }
  }
  return p;
}

# This function may fork
function get_port_for_service(default, ipproto, proto)
{
  local_var	k, p;
  # Remember: no KB yet in command line mode!
  if (! ipproto) ipproto = "tcp";
  if (ipproto == "tcp") k = "Services/" + proto;
  else k = "Services/" + ipproto + "/" + proto;
  p = get_kb_item(k);
  if (p) return p;
  k = "Known/" + ipproto + "/" + default;
  p = get_kb_item(k);
  if (p == proto) return default;
  exit(0, 'Service ' + ipproto + '/' + proto + ' was not detected');
}

function set_mysql_version(port, version)
{
  local_var	sb;
  sb = "mysql/version/" + port;
  set_kb_item(name: sb, value: version);
}

function get_mysql_version(port)
{
  local_var sb;
  sb = "mysql/version/" + port;
  return  get_kb_item(sb);
}

function get_kb_banner(port, ipproto, type)
{
  if (isnull(port))
  {
    display('get_kb_banner: missing argument port\n');
    return NULL;
  }
  port = int(port);
  if (port < 1 || port > 65535)
  {
   display('get_kb_banner: invalid port ', port, '\n');
   return NULL;
  }
  if (isnull(type))
  {
    display('get_kb_banner: missing argument type\n');
    return NULL;
  }
  if (isnull(ipproto)) ipproto = 'tcp';

  return get_kb_blob("FindService/"+ipproto+"/"+port+"/"+type);
}

function set_kb_banner(port, ipproto, type, banner)
{
  if (isnull(port))
  {
    display('set_kb_banner: missing argument port\n');
    return NULL;
  }
  port = int(port);
  if (port < 1 || port > 65535)
  {
   display('set_kb_banner: invalid port ', port, '\n');
   return NULL;
  }
  if (isnull(type))
  {
    display('set_kb_banner: missing argument type\n');
    return NULL;
  }
  if (isnull(ipproto)) ipproto = 'tcp';

  replace_kb_blob( name: "FindService/"+ipproto+"/"+port+"/"+type,
  	  	   value: banner );
}

function get_unknown_banner2(port, ipproto, dontfetch)
{
  local_var	sb, sbH, banner, soc, req, tcp, p, bannerHex;
  local_var	type;

  if (port < 1 || port > 65535)
  {
   display('get_unknown_banner2: invalid port ', port, '\n');
   return NULL;
  }
  if (! ipproto) ipproto = "tcp";
  if ( ipproto == "tcp" )
	tcp = 1;
  else
	tcp = 0;

  if ( tcp )
  {
   #
   # Try the banners from find_service first
   #
   foreach p (make_list("spontaneous", "get_http", "help"))
   {
     banner = get_kb_blob("FindService/"+ipproto+"/"+port+"/"+p);
     if (! isnull(banner)) return make_list(banner, p);
   }

   #
   # Fall back on the unknown banners
   #
   sb  = "unknown/banner/" + port;
  }
  else
  {
   sb  = "unknown/banner/" + ipproto + "/" + port;
  }
  banner = get_kb_blob(sb);
  if (!isnull(banner)) return make_list(banner, '?');

  # This comes from GizaNE_tcp_scanner
  banner = get_kb_item("BannerHex/"+port);
  if (!isnull(banner)) return make_list(hex2raw(s: banner), 'spontaneous');
  banner = get_kb_item("Banner/"+port);
  if (!isnull(banner)) return make_list(banner, 'spontaneous');

  banner = get_kb_item("Amap/"+ipproto+"/"+port+"/FullBanner");
  if (!isnull(banner)) return make_list(banner, 'amap');

  if (dontfetch) return(NULL);
  if (! get_port_state(port)) return (NULL);
  if (! tcp) return (NULL);

  soc = open_sock_tcp(port);
  if(!soc) return (NULL);
  # I don't think that it makes sense to send an HTTP request
  #req = http_head(item:"/", port:port);
  #send(socket:soc, data:req);
  banner = recv(socket:soc, length:2048);
  close(soc);
  if (!isnull(banner))
  {
   replace_kb_blob(name: sb, value: banner);
   return make_list(banner, 'spontaneous');
  }
  else return NULL;
}

function get_unknown_banner(port, ipproto, dontfetch)
{
 local_var	a;
 a = get_unknown_banner2(port:port, ipproto:ipproto, dontfetch:dontfetch);
 if (isnull(a)) return NULL;
 return a[0];
}

function set_unknown_banner(port, banner, ipproto)
{
  local_var	sb;
  if (!banner) return NULL;

  if (! ipproto || ipproto == 'tcp')
    sb = "unknown/banner/" + port;
  else
    sb = 'unknown/banner/' + ipproto + '/' + port;
  replace_kb_blob(name: sb, value: banner);
}

#
# Get the banner for a given service
# You must also specify a default port, in case this is not in the kb
#
function get_service_banner_line(service, port, ipproto)
{
  local_var	banner, soc, key, gport, tcp;
  tcp = !ipproto || ipproto == 'tcp';
  if (tcp)
   gport = get_kb_item("Services/" + service);
  else
   gport = get_kb_item("Services/" + ipproto + "/" + service);
  if(!gport) gport = port;

  if (tcp)
   key = service + "/banner/" + gport;
  else
   key = service + "/banner/" + ipproto + "/" + gport;

  banner = get_kb_blob(key);

  if(!banner)
  {
    if (! tcp) return NULL;

    if(get_port_state(gport))
    {
      soc = open_sock_tcp(gport);
      if(soc)
      {
	banner = recv_line(socket:soc, length:2048);
	close(soc);
      }
    }
#   if (banner) set_kb_item(name: key, value: banner);
  }

  return(banner);
}

#
function rand_str(length, charset)
{
  local_var	l, i, s, n;

  if (! charset)
   charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  if (isnull(length))
    length = 8;
  l = strlen(charset);
  s = "";
  for (i = 0; i < length; i ++)
  {
    n = rand() % l;
    s += charset[n];
  }
  return s;
}

function mult_str(str, nb)
{
  return crap(data: str, length: strlen(str) * nb);
}

function add_port_in_list(list, port)
{
 local_var l;

 if(!get_port_state(port))
 {
  if(isnull(list))return make_list();
  else return make_list(list);
 }

 if(isnull(list))return make_list(port);
 else list = make_list(list);

 foreach l (list)
 {
  if(l == port)
   return list;
 }

 return make_list(list, port);
}

# hex2raw was written by Renaud

function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) {
	display("hex2raw: odd string: ", s, "\n");
	l --;
	}
 s = tolower(s);
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

function report_service(port, svc, banner)
{
 local_var	k, name, a;

 svc = tolower(svc);
 if (! isnull(banner))
 {
  k = svc + "/banner/" + port;
  replace_kb_item(name: k, value: banner);
 }
 register_service(port: port, proto: svc);
 if (svc == 'www') name = 'web server';
 else if (svc == 'proxy') name = 'web proxy';
 else if (svc == 'hylafax-ftp' || svc == 'hylafax') name = 'HylaFAX server';
 else if (svc == 'agobot.fo') name = 'Agobot.fo backdoor';
 else if (svc == 'unknown_irc_bot') name = 'IRC bot';
 else if (svc == 'auth') name = 'identd';
 else name = toupper(svc) +' server';
 if (toupper(svc) == "FTP") a = 'An ';
 else
 {
  a = tolower(name[0]);
  if (a == 'a' || a == 'e' || a == 'i' || a == 'o') a = 'An ';
  else a = 'A ';
 }
 security_note(port: port, extra: a + name + ' is running on this port');
}

function make_service_list()
{
 local_var	p, l, k, oldport;

 foreach k (_FCT_ANON_ARGS)
 {
  if (typeof(k) == 'int' || typeof(k) == 'array')
   if (isnull(l))
    l = make_list(k);
   else
    l = make_list(l, k);
  else if (typeof(k) == 'string' || typeof(k) == 'data')
  {
   p = get_kb_list(k);
   if (!isnull(p))
    if (isnull(l)) l = make_list(p);
    else l = make_list(l, p);
  }
  else
   display(SCRIPT_NAME, ': unknown arg type ', typeof(k), ' in function make_list\n');
 }
 k = sort(l); l = NULL;
 foreach p (k)
 {
  if (p != oldport)
   if (isnull(l)) l = make_list(p);
   else l = make_list(l, p);
  oldport = p;
 }
 return l;
}

function base64_decode(str)
{
 local_var len, i, j, k, ret, base64, b64, a,b,c,o;
 len = strlen(str);
 if (len % 4 != 0) return "";

 ret = "";

 base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

 for (i = 0; i < 256; i++)
   b64[i] = 0;
 for (i = 0; i < strlen(base64); i++)
   b64[ord(base64[i])] = i;

 for(j=0;j<len;j+=4)
 {
   for (i = 0; i < 4; i++)
   {
    c = ord(str[j+i]);
    a[i] = c;
    b[i] = b64[c];
   }

   o[0] = (b[0] << 2) | (b[1] >> 4);
   o[1] = (b[1] << 4) | (b[2] >> 2);
   o[2] = (b[2] << 6) | b[3];
   if (a[2] == ord('='))
     i = 1;
   else if (a[3] == ord('='))
     i = 2;
   else
     i = 3;
   for(k=0;k<i;k++)
      ret += raw_string(int(o[k]) & 255);

   if (i < 3)
     break;
 }

 return ret;
}

global_var __base64_code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function base64_code(c)
{
 return(__base64_code[c]);
}

function pow2(x)
{
 local_var __ret;

 __ret = 1;
 while(x)
  {
  __ret = __ret * 2;
  x = x  - 1;
  }
 return(__ret);
}

function base64(str)
{
 local_var len, i, ret, char_count, _bits, val, cnt, mul;
 len = strlen(str);
 i = 0;
 ret = "";
 char_count = 0;
 _bits = 0;
 while(i < len)
 {
  _bits = _bits + ord(str[i]);
  char_count = char_count + 1;
  if(char_count == 3)
  {
    val = _bits / 262144;
    ret += base64_code(c:val);
    val = _bits / 4096;
    val = val & 0x3F;
    ret += base64_code(c:val);
    val = _bits / 64;
    val = val & 0x3F;
    ret += base64_code(c:val);
    val = _bits & 0x3F;
    ret += base64_code(c:val);
    char_count = 0;
    _bits = 0;
 }
 else {
       _bits = _bits * 256;
       }
 i = i + 1;
 }


 if(!(char_count == 0))
 {
  cnt = char_count * 8;
  mul = 16;
  mul = mul - cnt;
  mul = pow2(x:mul);
  _bits = _bits * mul;
  val = _bits / 262144;
  ret += base64_code(c:val);
  val = _bits / 4096;
  val = val & 0x3F;
  ret += base64_code(c:val);
 if(char_count == 1)
 {
  ret += '==';
 }
 else
 {
   val = _bits / 64;
   val = val & 0x3F;
   ret +=  base64_code(c:val) + '=';
  }
 }
 return(ret);
}

# This function converts a string representing a decimal number to
# to hexadecimal; eg, dec2hex(1098757090) == "417db3e2".
#
# Args:
#   o num, decimal number.
#
# Return:
#   hex number represented as a raw string.
#
# updated: 16-Nov-2004, George A. Theall
#
function dec2hex(num) {
  local_var digits, hex, rem;
  hex = "";

  num = uint(num);
  while (num > 0) {
    rem = num % 256;
    hex = raw_string(rem, hex);
    num = num / 256;
    if (num > 0 && num < 255) {
      hex = raw_string(num, hex);
      num = 0;
    }
  }
  if (!hex) hex = raw_string(0x00);

  return hex;
}

##
# @remark Convert a 32-bit, unsigned integer to a hexdecimal string
# representation. Does not preprend it with '0x'.
# @param num integer, the number to be formatted
# @param width, the character width of the string representation
# desired (optional; if not supplied the function will return a
# string of the minimum necessary width).
# @anonparam num may also be passed as an anonymous parameter, for
# convenience. This also makes the function more useful for mapping,
# and use with other higher-order functions.
# @return string representing num in hexidecimal format
##
function int2hex(num, width) {
  local_var hinum, lonum, tophalf, lohalf, len, res;
  if (isnull(num)) num = _FCT_ANON_ARGS[0];
  hinum = (0xFFFF & ((num & 0xFFFF0000) >> 16));
  lonum = (0xFFFF & num);
  if (hinum)
    tophalf = hexstr(dec2hex(num:hinum));
  else
    tophalf = '';

  lohalf = hexstr(dec2hex(num:lonum));
  len = strlen(lohalf);
  if(len < 4)
    lohalf = crap(data:'0', length:4-len) + lohalf;

  res = tophalf + lohalf;
  if (!isnull(width))
  {
    len = strlen(res);
    if (len < width) res = crap(data:'0', length:(width-len)) + res;
  }
  return res;
}



# Convert a Date CVS field to Unix time
# Michel Arboi

function cvsdate2unixtime(date)
{
  local_var v, u;
  if (! defined_func("mktime")) return NULL;	# We could write it in NASL...
  v = pregmatch(string: date, pattern: ".Date: ([0-9]+)/([01][0-9])/([0-3][0-9]) ([0-2][0-9]):([0-6][0-9]):([0-6][0-9]) \$");
  if (isnull(v)) return NULL;
  u = mktime(year: v[1], mon: v[2], mday: v[3], hour: v[4], min: v[5], sec: v[6]);
  return u;
}


function get_unknown_svc()
{
 local_var p;

 p = get_kb_item("Services/unknown");
 if ( ! p )
 {
   p = _FCT_ANON_ARGS[0];
   if (! p) return 0;	# In case no arg is given
 }
 if ( p == 135 || p == 139 || p == 445 ) return 0;
 if ( ! service_is_unknown(port:p)) return 0;
 return p;
}

##
# Selects values of Services/unknown where service_is_unknown is TRUE.
# No forking occurs.
#
# @return ports of unknown services
##
function get_unknown_svc_list()
{
  local_var uports, ports, port;

  uports = get_kb_list("Services/unknown");
  if (isnull(uports))
    return make_list();

  ports = make_list();
  foreach port (uports)
  {
    if (service_is_unknown(port:port))
      ports = make_list(ports, port);
  }

  return ports;
}

function get_3digits_svc()
{
 local_var p;

 p = get_kb_item("Services/three_digits");
 if ( ! p ) return _FCT_ANON_ARGS[0];
 if ( p == 135 || p == 139 || p == 445 ) return 0;
 if ( ! service_is_unknown(port:p)) return 0;
 return p;
}

function save_version_in_kb(key, ver)
{
  if (isnull(key)) return NULL;

  local_var i, item, matches, part;

  if (isnull(ver)) ver = "";
  # nb: convert ver as a string to an array with 4 elements for numbers
  # and a fifth for any non-digits; eg,
  #
  # "1.0a" => ['0': 1]['1': 0]['2': 0]['3': 0]['4': a]
  # "1.5" => ['0': 1]['1': 5]['2': 0]['3': 0]['4': ]
  # "1.5.0.6" => ['0': 1]['1': 5]['2': 0]['3': 6]['4': ]
  # "1.2.3.4.5.6" => ['0': 1]['1': 2]['2': 3]['3': 4]['4': 5.6]
  if (typeof(ver) == "string" || typeof(ver) == "data")
  {
    item = ver;
    ver = make_list();
    for (i=0; i<4; i++)
    {
      matches = pregmatch(pattern:"^([0-9]+)\.?", string:item);
      if (matches)
      {
        ver[i] = matches[1];
        item = item - matches[0];
      }
      else break;
    }
    while (i < 4)
      ver[i++] = "0";
    ver[4] = item;
  }
  else if (typeof(ver) != "array") return NULL;

  item = "";
  foreach part (ver)
  {
    if ("~|~" >< part) return NULL;
    else if ("," >< part) part = str_replace(find:",", replace:"~|~", string:part);
    item += part + ",";
  }
  item = ereg_replace(pattern:',$', replace:'', string:item);

  set_kb_item(name:key, value:item);
  return item;
}

function read_version_in_kb()
{
  local_var i, item, key, ver;

  key = _FCT_ANON_ARGS[0];
  if (isnull(key)) return NULL;

  item = get_kb_item(key);
  if (isnull(item)) return NULL;

  ver = split(item, sep:',', keep:FALSE);
  # nb: split() ignores an empty final element so add it back.
  if (max_index(ver) == 4) ver[4] = "";
  else if (max_index(ver) != 5) return NULL;
  for (i=0; i<4; i++)
    if (strlen(ver[i])) ver[i] = int(ver[i]);
  if (strlen(ver[4]) && "~|~" >< ver[4])
      str_replace(find:"~|~", replace:",", string:ver[4]);

  return ver;
}

# This function is duplicated in ping_host.nasl
function difftime(t1, t2)
{
 local_var	s1, s2, u1, u2, v;

 v = split(t1, sep: '.', keep: 0);
 s1 = int(v[0]);
 u1 = int(v[1]);
 v = split(t2, sep: '.', keep: 0);
 s2 = int(v[0]);
 u2 = int(v[1]);
 return (u2 - u1) + (s2 - s1) * 1000000;
}

function list_uniq()
{
  local_var item, list, res, seen;

  list = make_list(_FCT_ANON_ARGS[0]);
  seen = make_array();
  res = make_list();
  foreach item (list)
    if (!seen[item]++) res = make_list(res, item);

  return res;
}

function get_read_timeout()
{
  local_var	timeout;
  timeout = int(get_preference("checks_read_timeout"));
  if (timeout <= 0) timeout = 5;
  return timeout;
}

function substr_at_offset(str, blob, offset)
{
 local_var	l;
 l = strlen(blob);
 if (l == 0) return 1;
 if (
   strlen(str) > (l+offset-1) &&
   substr(str, offset, offset + l - 1) == blob
 ) return 1;
 else return 0;
}

function get_kb_item_or_exit(msg, exit_code)
{
  local_var	kb, v;
  kb = _FCT_ANON_ARGS[0];
  if (isnull(kb)) exit(1, "A KB key wasn't provided to get_kb_item_or_exit().");
  v = get_kb_item(kb);
  if (! isnull(v)) return v;

  if (isnull(msg))
    msg = "The '"+kb+"' KB item is not set.";
  if (isnull(exit_code)) exit_code = 0;
  exit(exit_code, msg);
  #NOTREACHED
}

##
# Retrieves the desired item from the global KB and exits if it fails.
#
# @anonparam kb key name/pattern to retrieve from the KB
# @param msg audit message to use if exiting
# @param exit_code exit status to use if exiting
#
# @return the desired KB items if they were found
##
function get_global_kb_item_or_exit(msg, exit_code)
{
  local_var kb, v;
  kb = _FCT_ANON_ARGS[0];
  if (!defined_func("get_global_kb_item")) exit(1, "get_global_kb_item() is not defined.");
  if (isnull(kb)) exit(1, "A KB key wasn't provided to get_global_kb_item_or_exit().");
  v = get_global_kb_item(kb);
  if (! isnull(v)) return v;

  if (isnull(msg))
    msg = "The '"+kb+"' global KB item is not set.";
  if (isnull(exit_code)) exit_code = 0;
  exit(exit_code, msg);
  #NOTREACHED
}

##
# retrieves the desired items from the KB, or exits if none were found
#
# @anonparam kb        key name/pattern to retrieve from the KB
# @param     msg       audit message to use if exiting
# @param     exit_code exit status to use if exiting
#
# @return a hash of the desired KB items if they were found (same return value as get_kb_list())
##
function get_kb_list_or_exit(msg, exit_code)
{
  local_var	kb, v;
  kb = _FCT_ANON_ARGS[0];
  if (isnull(kb)) exit(1, "A KB key wasn't provided to get_kb_list_or_exit().");
  v = get_kb_list(kb);
  if (! isnull(v)) return v;

  if (isnull(msg))
    msg = "No '"+kb+"' KB items are set.";
  if (isnull(exit_code)) exit_code = 0;
  exit(exit_code, msg);
  #NOTREACHED
}

##
# retrieves only one KB value for a given kb key, or NULL if none were found
#
# @anonparam kb        key name/pattern to retrieve from the KB
#
# @return the first value from the first key of the array response of get_kb_list(),
function get_one_kb_item()
{
  local_var kb, v, k;
  kb = _FCT_ANON_ARGS[0];
  if (empty_or_null(kb)) return NULL;
  v = get_kb_list(kb);
  if (empty_or_null(v)) return NULL;
  k = keys(v);
  return v[k[0]];
}

function join(sep)
{
  local_var	i, n, str, list, k;
  if (isnull(sep)) sep = ' ';
  list = NULL;
  foreach k (_FCT_ANON_ARGS)
  {
    if (isnull(k)) continue;

    if (isnull(list))
      list = make_list(k);
    else
      list = make_list(list, k);
  }
  n = max_index(list) - 1;
  str = "";
  if (n < 0) return str;
  for (i = 0; i < n; i ++)
    str = str + list[i] + sep;
  str += list[n];
  return str;
}

##
# Compares two strings representing versions.
#
# @param app     A key for the internal array of regexes, avoids
#                needing to have the list of regexes for well-known
#                applications in each plugin.
# @param fix     The second version string.
# @param minver  A version string to check that ver is greater than
#                or equal to.
# @param regexes An array of capturing regexes to handle non-numeric
#                suffixes of the version strings. See code for
#                details.
# @param strict  Require ver and fix to have an equal number of
#                fields, otherwise this function returns 0. TRUE by
#                default. strict is incompatible with the app and
#                regexes.
# @param ver     The first version string.
#
# @remark This function currently only handles numeric version
#         strings, and will refuse to compare when [a-zA-Z]
#         characters are found.
#
# @remark This function currently only handles a single regex
#         replacement. The first matching regex will mangle the
#         version string, and subsequent matches will be ignored.
#
# @remark The well-known applications currently supported are:
#         - asterisk
#
# @return -1 if ver < fix
#          0 if ver == fix,
#          1 if ver > fix,
#          NULL if an error condition is encountered or
#               strict is true and vlen != flen or
#               if minver > ver
##
function ver_compare(app, fix, minver, regexes, strict, ver)
{
  local_var ffield, flen, i, key, minresult, regex, suffixes;
  local_var values, vfield, vlen, vstr;

  # This is the array of regexes for well-known applications.
  suffixes = make_array();

  suffixes["asterisk"] = make_array(
    -2, "-beta(\d+)",
    -1, "-rc(\d+)",
    1, "-cert(\d+)"
  );

  # Check for minimum version if that argument is provided
  if (!empty_or_null(minver))
  {
    minresult = ver_compare(ver:ver, fix:minver, strict:strict, app:app, regexes:regexes);
    if ( isnull(minresult) || minresult < 0)
    {
      return NULL;
    }
  }

  # Strict is on by default, except when using version mangling.
  if (isnull(strict))
  {
    strict = (isnull(app) && isnull(regexes));
  }
  else if (strict && (!isnull(app) || !isnull(regexes)))
  {
    debug_print("ver_compare(): 'strict' cannot be set to TRUE when version mangling is used.");
    return NULL;
  }

  # In the event lists are provided, convert them to strings.
  ver = join(ver, sep:".");
  fix = join(fix, sep:".");

  # Perform version mangling with either a set of well-known or ad-hoc
  # regexes, the former being preferred.
  if (!isnull(app))
  {
    if (isnull(suffixes[app]))
    {
      debug_print("ver_compare(): '", app, "' is not a well-known application.");
      return NULL;
    }
    suffixes = suffixes[app];
  }
  else if (!isnull(regexes))
  {
    suffixes = regexes;
  }
  else
  {
    suffixes = NULL;
  }

  if (!isnull(suffixes))
  {
    # Sort the values assigned to each suffix so that we can attempt
    # mangling in ascending order.
    values = make_list();
    foreach key (keys(suffixes))
    {
      values = make_list(values, int(key));
    }

    values = sort(values);

    # Mangle both version strings that were passed in so that the caller
    # doesn't have to manually mangle the versions for the fixed
    # version.
    vstr = make_list(ver, fix);
    for (i = 0; i < 2; i++)
    {
      foreach key (values)
      {
        regex = suffixes[key];

        if (vstr[i] =~ regex)
        {
          # We'll be adding two fields to the version string:
          #   1. Represents the ordinal value of the suffix.
          #   2. Represents the value attached to the suffix.
          vstr[i] = ereg_replace(
	    string  : vstr[i],
	    pattern : regex,
	    replace : "." + key + ".\1"
          );

          break;
        }
      }
    }

    ver = vstr[0];
    fix = vstr[1];
  }

  # If any non-numeric portions of the version string remain, we
  # have not properly handled the input, so scream and die.
  regex = "^[-\d]+(\.[-\d]+)*$";
  if (ver !~ regex || fix !~ regex)
  {
    debug_print("ver_compare(): Invalid argument ver='", ver, "' or fix='", fix, "'.");
    return NULL;
  }

  # Break apart the version strings into numeric fields.
  ver = split(ver, sep:'.', keep:FALSE);
  fix = split(fix, sep:'.', keep:FALSE);

  # Both versions must have the same number of fields when
  # when doing a strict comparison.
  vlen = max_index(ver);
  flen = max_index(fix);
  if (strict && vlen != flen)
    return NULL;

  # Compare each pair of fields in the version strings.
  for (i = 0; i < vlen || i < flen; i++)
  {
    vfield = int(ver[i]);
    ffield = int(fix[i]);

    if (vfield < ffield)
      return -1;

    if (vfield > ffield)
      return 1;
  }

  return 0;
}

function ver_num()
{
  local_var ver;
  ver = _FCT_ANON_ARGS[0];

  if (isnull(ver)) return 0;

  return max_index(split(ver, sep:'.', keep:FALSE));
}

# Remove leading and trailing white space from a string
#
# @param ANON string to strip
# @param pattern pattern of characters to strip from the string
#
# @return stripped string
function strip(pattern)
{
  local_var value, e, i;

  value = _FCT_ANON_ARGS[0];

  if(empty_or_null(value))
  {
    return value;
  }

  if(isnull(pattern))
  {
    pattern = ' \t\n\r';
  }

  e = strlen(value);

  for(i = 0; i < e && value[i] >< pattern; i ++) { };
  for(e = strlen(value) - 1; value[e] >< pattern && e > 0; e --) { };

  value = substr(value, i, e);

  return value;
}

##
# Extracts key->value pair from line in properties file.
#
# @param str valid non-zero length string
# @param sep string of characters that will be used to separate
#            key->value pairs
# @remark    sep defaults to ':= '.
#
# @return array s.t. ret['key'] == key && ret['value'] == value.
#         NULL if key and value not found.
##
function get_key_and_value(str, sep)
{
  local_var key;        # Extracted key.
  local_var value;      # Extracted value.
  local_var key_index;  # Index where key starts.
  local_var prev_char;  # Buffer for prev. examined char.

  # Function can accept argument anonymously.
  if (isnull(str)) str = _FCT_ANON_ARGS[0];
  if (isnull(sep)) sep = ":= ";

  # Validate that we were passed an argument.
  if (isnull(str))
  {
    err_print('get_key_and_value(): was not passed an argument.');
    return NULL;
  }

  # Explicitly convert the argument to a string.
  str = string(str);

  # Validate that input is a non-zero-length string.
  if (strlen(str) <= 0)
  {
    err_print('get_key_and_value(): was passed a zero-length string.');
    return NULL;
  }

  key_index = -1;
  prev_char = NULL;

  # Extract the key by looking for the first unescaped
  # '=', ':', or whitespace (unless custom sep is specified).
  local_var i;

  sep = "^[" + sep + "]$";
  for (i = 0; i < strlen(str); i++)
  {
    if (str[i] =~ sep && prev_char != '\\')
    {
      key_index = i;
      break;
    }
    else prev_char = str[i];
  }
  if (key_index != -1)
  {
    key = substr(str, 0, key_index - 1);
    if (key) key = strip(key);

    value = substr(str, key_index + 1);
    if (value) value = strip(value);

    return make_array('key', key, 'value', value);
  }
  else return NULL;
}

##
# Parses a string as a set of Java properties.
#
# @param str a valid non-zero-length string.
# @param sep string of characters that are used to separate key->value
#            pairs
#
# @return array of key->value pairs extracted from str.
#         NULL  if no valid keys.
##
function parse_properties(str, sep)
{
  local_var properties;     # Extracted properties to be returned.
  local_var lines;          # Lines in str.
  local_var keys_exist;     # Boolean for whether there are keys.

  # Function can accept argument anonymously.
  if (isnull(str)) str = _FCT_ANON_ARGS[0];

  # Validate that we were passed an argument.
  if (isnull(str))
  {
    err_print('parse_properties(): was not passed an argument.');
    return NULL;
  }

  # Explicitly convert the argument to a string.
  str = string(str);

  # Validate that input is a non-zero-length string.
  if (strlen(str) <= 0)
  {
    err_print('parse_properties(): was passed a zero-length string.');
    return NULL;
  }

  # Split the string into lines.
  lines = split(str);
  keys_exist = FALSE;

  # Process each line.
  local_var i;
  for (i = 0; i < max_index(lines); i++)
  {
    local_var line;         # Trimmed version of the line.
    local_var key_value;    # Key and value pair.

    # Ignore blank lines.
    if (!chomp(lines[i])) continue;

    line = strip(lines[i]);

    # If line is a comment, ignore.
    if (line[0] =~ "^[!#]$") continue;

    # If line ends with '\', concatenate it to the next line.
    if (line[strlen(line) - 1] == '\\')
    {
      lines[i+1] = line + lines[i+1];
      continue;
    }

    # Extract key and value from line.
    key_value = get_key_and_value(line, sep:sep);
    if (!isnull(key_value))
    {
      properties[key_value['key']] = key_value['value'];
      keys_exist = TRUE;
    }
    else continue;
  }

  # If we extracted any properties, return the array, otherwise return
  # NULL.
  if (max_index(keys(properties)) > 0) return properties;
  else return NULL;
}

#
# Return value:
# -1	timeout - an IPS is probably on the way
#  0	connection successful: the service is alive
#  1	RST received: the service is dead.
#
function service_is_dead(port, try, exit)
{
  local_var	soc, i, e, to, tictac;

  if (isnull(port))
  {
    err_print('service_is_dead: missing port argument');
    return NULL;
  }

  if (try <= 0) try = 3;

  to = get_read_timeout();
  for (i = try; i > 0; i --)
  {
    if (! defined_func("socket_get_error"))
    {
      tictac = unixtime();
      soc = open_sock_tcp(port);
      if (soc)
      {
        close(soc);
	if (exit)
          exit(0, "The service on port "+port+" is still alive.");
        else
	  return 0;
      }
      else
      {
        # No timeout => RST received
        if (unixtime() - tictac < to - 1)
	  return 1;
      }
    }
    else	# GizaNE 4.x
    {
      soc = open_sock_tcp(port, nonblocking:TRUE);
      while (1)
      {
        if (socket_ready(soc))
        {
          e = socket_get_error(soc);
 	  close(soc);
 	  if (e == 0)
	    if (exit)
	      exit(0, "The service on port "+port+" is still alive.");
	    else
	      return 0;
	  else
  	  {
	    if (e == ECONNREFUSED)
	      return 1;
	    else
	      break;
	  }
	}
        sleep(1);
      }
      #NOTREACHED
    }
    if (i > 1) sleep(1);
  }
  if (exit)
    exit(1, "An IPS may be in the way.");
  else
    return -1;
}

function scanned_ports_list(ipproto)
{
  local_var	pl, l, p, prefix;

  l = make_list();
  if (isnull(ipproto)) ipproto = 'tcp';
  prefix = "Ports/"+ipproto+"/";
  pl = get_kb_list(prefix+"*");
  if (isnull(pl)) return l;
  foreach p (keys(pl))
  {
    l = make_list(l, int(p - prefix));
  }
}

#### KB functions that support binary / big data ####

# Prefixes:
# P:	plain data
# B64:	base 64
# Zxxx:	zlib (+ base64) - xxx = original size

function decode_kb_blob(name, value)	# Name is for debug only
{
  local_var	type, len, i;

  if (isnull(value)) return NULL;

  len = strlen(value);
  if (len == 0)
  {
    err_print('decode_kb_blob: empty blob ', name, '\n');
    return NULL;
  }
  i = stridx(value, ':');
  if (i < 1)
  {
    err_print('decode_kb_blob: invalid blob ', name, '\n');
    return NULL;
  }
  type = substr(value, 0, i - 1);
  if (len <= i) value = ''; else value = substr(value, i + 1);
  if (type == 'P')
    return value;
  if (type == 'B64')
    return base64_decode(str: value);
  if (type[0] == 'Z')
  {
    len = int(substr(type, 1));
    value = base64_decode(str: value);
    value = zlib_decompress(data: value, length: len);
    return value;
  }
  err_print('decode_kb_blob: invalid type ', type, ' for blob ', name, '\n');
  return NULL;
}

function encode_kb_blob(value)
{
  local_var	len, len2, zval, bin;

  if ('\0' >< value) bin = 1; else bin = 0;

  if (defined_func("zlib_compress"))
  {
    len = strlen(value);
    # Compressing short data uses CPU for no gain
    if (len > 128 || bin && len > 96)
    {
      zval = zlib_compress(data: value, level: 9);
      if (! isnull(zval))
      {
        len2 = strlen(zval);
	if (! bin) { len2 *= 4; len2 /= 3; }
        if (len2 < len)
	  return 'Z'+ len + ':' + base64(str:zval);
      }
    }
  }

  if (bin)
    return 'B64:'+base64(str:value);
  else
    return 'P:'+value;
}

function set_kb_blob(name, value)
{
  if (isnull(name) || isnull(value))
  {
    err_print('set_kb_blob: missing parameter name or value\n');
    return;
  }
  set_kb_item(name: name, value: encode_kb_blob(value: value));
}

function get_kb_blob()
{
  local_var	name, value;

  name = _FCT_ANON_ARGS[0];

  value = get_kb_item(name);
  return decode_kb_blob(name: name, value: value);
}

function get_kb_blob_list()
{
  local_var kb, encoded, decoded, key;

  kb = _FCT_ANON_ARGS[0];
  if (isnull(kb)) exit(1, "A KB key wasn't provided to get_kb_blob_list().");

  encoded = get_kb_list(kb);
  if (isnull(encoded)) return NULL;

  decoded = make_array();
  foreach key (keys(encoded))
    decoded[key] = decode_kb_blob(value:encoded[key]);

  return decoded;
}

function get_kb_blob_list_or_exit(msg, exit_code)
{
  local_var kb, v;
  kb = _FCT_ANON_ARGS[0];
  if (isnull(kb)) exit(1, "A KB key wasn't provided to get_kb_blob_list_or_exit().");
  v = get_kb_blob_list(kb);
  if (! isnull(v)) return v;

  if (isnull(msg))
    msg = "No '"+kb+"' KB items are set.";
  if (isnull(exit_code)) exit_code = 0;
  exit(exit_code, msg);
  #NOTREACHED
}

function rm_kb_blob(name, value)
{
  if (isnull(value))
    rm_kb_item(name: name);
  else
    rm_kb_item(name: name, value: encode_kb_blob(value: value));
}

function replace_kb_blob(name, value)
{
  replace_kb_item(name: name, value: encode_kb_blob(value: value));
}

##
# Generate a UUID.
#
# @param ver The version of UUID to generate, default is 4
# Generate a UUID.
#
# @param ver The version of UUID to generate, default is 4
# @param hyphens Determines if hyphens should be placed in UUID for easier readability,
#                default is TRUE
#
# @remark This function only currently supports version 4 (random)
#         UUIDs.
#
# @return A string in UUID format.
##
function generate_uuid(ver, hyphens)
{
  local_var uuid, xdigit;

  # Set defaults.
  if (isnull(ver))
    ver = 4;

  if (isnull(hyphens))
    hyphens = TRUE;

  # Version 4 UUIDs are random except for two characters.
  if (ver == 4)
  {
    uuid = NULL;

    if (hyphens)
      uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    else
      uuid = "xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx";

    # Replace the Xs.
    while ("x" >< uuid)
    {
      xdigit = hex(rand() % 16);
      uuid = str_replace(string:uuid, find:"x", replace:xdigit[3], count:1);
    }

    # Replace the Y.
    xdigit = hex(rand() % 4 + 8);
    uuid = str_replace(string:uuid, find:"y", replace:xdigit[3], count:1);

    return uuid;
  }

  return NULL;
}

##
# Fork for each element in an array or a list, giving the children
# distinct elements.
#
# @anonparam list The list or array to distribute.
#
# @param fork  Whether the fork should actually occur, true by
#              default.
# @param id    Specifies an additional string in the key used to
#              branch, random by default.
# @param key   Whether the keys should be distributed, false by
#              default.
# @param value Whether the values should be distributed, true by
#              default.
#
# @return A single key, value, or key/value pair as a list.
##
function branch(fork, id, key, value)
{
  local_var k, kb, keys, list, v;

  # Set defaults.
  if (isnull(fork))
    fork = TRUE;

  if (isnull(id))
    id = rand();

  if (isnull(key))
    key = FALSE;

  if (isnull(value))
    value = TRUE;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
  {
    err_print('branch: This function takes one argument.\n');
    return NULL;
  }

  list = _FCT_ANON_ARGS[0];
  if (typeof(list) != "array")
  {
    err_print('branch: This function only works on lists and arrays.\n');
    return NULL;
  }

  if (!key && !value)
  {
    err_print('branch: This function requires at least one of the key or value parameters to be true.\n');
    return NULL;
  }

  # Only fork if we've been asked to. This feature makes writing
  # control flow easier for functions that optionally fork.
  if (!fork)
    return list;

  # Both arrays and lists have keys, which are guaranteed to be
  # unique. Ensure that we've got keys to branch off of.
  keys = keys(list);
  if (isnull(keys) || max_index(keys) == 0)
    return NULL;

  # Store the list's keys in a temporary key in the KB, which we then
  # use to implicitly fork.
  kb = "/tmp/branch/" + SCRIPT_NAME + "/" + id + "/" + _branch_identifier;

  # Increment the branch identifier so that later branches won't use
  # the old branch's data.
  _branch_identifier++;

  # Ensure that there is nothing already in the KB that could cause
  # additional forks.
  rm_kb_item(name:kb);

  # Store the keys in the KB.
  foreach k (keys)
  {
    set_kb_item(name:kb, value:k);
  }

  # Branch off the KB, one key should come back to each child.
  k = get_kb_item_or_exit(kb);

  # Return the key, if requested.
  if (key && !value)
    return k;

  # Return the value, if requested.
  v = list[k];
  if (!key && value)
    return v;

  # Return the key/value pair, if requested.
  list = make_list();
  list[0] = k;
  list[1] = v;

  return list;
}

##
# Creates an array without flattening the values.
#
# @anonparam key The key to store the data under.
# @anonparam val The data to be stored.
#
# @param array An array to add keys to.
#
# @return The new or updated array.
##
function make_nested_array(array)
{
  local_var i, max, result;

  if (isnull(array))
    array = make_array();

  max = max_index(_FCT_ANON_ARGS);
  for (i = 0; i < max - 1; i += 2)
  {
    array[_FCT_ANON_ARGS[i]] = _FCT_ANON_ARGS[i + 1];
  }

  if (max % 2 != 0)
    err_print("make_nested_array: odd number (" + max + ") of arguments.");

  return array;
}

##
# Creates a list without flattening the elements.
#
# @anonparam val The value to add to the list.
#
# @param list A list to append to.
#
# @return The new or updated list.
##
function make_nested_list(list)
{
  local_var i, j, max, result;

  if (isnull(list))
    list = make_list();

  j = max_index(list);
  max = max_index(_FCT_ANON_ARGS);
  for (i = 0; i < max; i++)
  {
    list[j++] = _FCT_ANON_ARGS[i];
  }

  return list;
}

##
# Determines whether the passed NASL object is an array or a list.
#
# @anonparam ds A data structure.
#
# @return TRUE if the object is a list, FALSE otherwise.
##
function is_list()
{
  local_var ds, ks;

  ds = _FCT_ANON_ARGS[0];

  # Lists appear to the typeof function as arrays.
  if (typeof(ds) != "array")
      return FALSE;
  ks = keys(ds);

  # If the data structure is empty, we can't base our decision on its
  # keys. So we use the fact that max_index() always returns the same
  # non-zero value for arrays.
  if (max_index(ks) <= 0)
    return (max_index(ds) == 0);

  # A non-empty array or list will have a number of keys. Each key in
  # an array is guaranteed to be of type data, and each key in a list
  # is guaranteed to be of type int. This means that we can check any
  # key for our answer.
  return (typeof(ks[0]) == "int");
}

##
# Sorts a list alphabetically (unlike sort() which sorts things asciibetically)
#
# @anonparam list list to sort
# @return alphabetically sorted listed
##
function alpha_sort()
{
  local_var list, hash, key, sorted_list, element;
  list = _FCT_ANON_ARGS[0];
  hash = make_array();
  sorted_list = make_list();

  # Case needs to be ignored to sort the list alphabetically ('aardvark' comes before 'AX').
  # A hash is used to keep track of the original representation of each string during/after sorting.
  # If multiple strings differ only by case ('FOO' and 'foo'), a list is used to keep track of them
  foreach element (list)
  {
    key = tolower(element);
    if (isnull(hash[key]))
      hash[key] = element;
    else
      hash[key] = make_list(hash[key], element);
  }

  # sort the list alphabetically, then asciibetically if there are any case
  # insensitive duplicates. for example, if the list contains 'foo' and 'Foo',
  # 'Foo' should come first
  foreach key (sort(keys(hash)))
  {
    if (typeof(hash[key]) != 'array')
      sorted_list = make_list(sorted_list, hash[key]);
    else
      sorted_list = make_list(sorted_list, sort(hash[key]));
  }

  return sorted_list;
}

##
# determine if a family or plugin is enabled. This should
# only be used for plugins that do not have dependencies
# and do not get dynamically enabled. This is specific for
# plugins using the ACT_END_REPORT script_category to
# determine if the plugin is enabled or disabled.
#
# @param [script_family:string] script_family for the plugin
# @param [plugin_id:string] plugin_id for the plugin
#
# @return bool TRUE enabled, FALSE disabled
##
function is_plugin_enabled(script_family, plugin_id)
{
  local_var fam_stat, plid_stat;

  fam_stat = get_preference("plugin_selection.family."+script_family);
  plid_stat = get_preference("plugin_selection.individual_plugin."+plugin_id);

  if (fam_stat == "disabled") return FALSE;
  else if (fam_stat == "enabled" || isnull(fam_stat)) return TRUE;
  else if (fam_stat == "mixed" && plid_stat == "enabled") return TRUE;
  else return FALSE;
}

function assert(flag, line, msg)
{
  if (isnull(line)) line = "<unknown>";

  if (isnull(msg)) msg = "Failed.";

  if (flag != FALSE && flag != TRUE)
  {
    flag = ereg_replace(string:obj_rep(flag), pattern:"\n\s*", replace:"");
    exit(1, "ASSERT::" + line + ": Passed a non-boolean value " + flag + ".");
  }

  if (!flag) exit(1, "ASSERT::" + line + ": " + msg);
}

function assert_eq(line)
{
  local_var expected, observed;

  if (max_index(_FCT_ANON_ARGS) != 2) assert(line:line, flag:FALSE, msg:"Wrong number of arguments passed to assert_eq.");

  expected = _FCT_ANON_ARGS[0];
  observed = _FCT_ANON_ARGS[1];

  if (typeof(expected) == "array" || typeof(observed) == "array")
  {
    if (obj_cmp(expected, observed)) return;
  }
  else if (expected == observed) return;

  expected = ereg_replace(string:obj_rep(expected), pattern:"\n\s*", replace:" ");
  observed = ereg_replace(string:obj_rep(observed), pattern:"\n\s*", replace:" ");

  assert(line:line, flag:FALSE, msg:"Expected `" + expected + "` but got `" + observed + "`.");
}

function assert_ne(line)
{
  local_var expected, observed;

  if (max_index(_FCT_ANON_ARGS) != 2) assert(line:line, flag:FALSE, msg:"Wrong number of arguments passed to assert_ne.");

  expected = _FCT_ANON_ARGS[0];
  observed = _FCT_ANON_ARGS[1];

  if (typeof(expected) == "array" || typeof(observed) == "array")
  {
    if (!obj_cmp(expected, observed)) return;
  }
  else if (expected != observed) return;

  expected = ereg_replace(string:obj_rep(expected), pattern:"\n\s*", replace:" ");

  assert(line:line, flag:FALSE, msg:"Expected to not get `" + expected + "`.");
}

##
# Returns the length of NASL objects.
#
# @param  any object The NASL object whose length we want.
# @remark This function returns the actual number of elements in a
#         sparse list, not the max index. Non-array types are coerced
#         into strings and we return the strlen() for them (so len(7)
#         would return 1.)
#
# @return int   number of elements in object, -1 if error occurs.
##
function len(object)
{
  # Accept first argument anonymously.
  if (isnull(object)) object = _FCT_ANON_ARGS[0];
  if (isnull(object))
  {
    err_print("len(): Missing required arg 'object'.");
    return -1;
  }

  # For lists/arrays, return number of elements.
  if (typeof(object) == 'array')
  {
    if (isnull(max_index(keys(object)))) return 0;
    else return max_index(keys(object));
  }

  # For everything else, coerce into a string and return strlen.
  if (typeof(object) == "string") return strlen(object);
  else return strlen(string(object));
}

##
# Returns the max length of elements in an array.
#
# @param  array elements  May be a list or array.
# @param  bool  same_type OPTIONAL, if TRUE ensures that each element
#                         in elements is of the same type.
#
# @return int   max length of elements in array or -1 if error occurred
##
function maxlen(elements, same_type)
{
  local_var element;
  local_var max;

  # Accept first argument anonymously.
  if (isnull(elements)) elements = _FCT_ANON_ARGS[0];
  if (isnull(elements))
  {
    err_print("len(): Missing required arg 'elements'.");
    return -1;
  }

  if (isnull(same_type)) same_type = FALSE;

  if (typeof(elements) != 'array')
  {
    err_print("maxlen(): arg 'elements' is not iterable.");
    return -1;
  }

  # If elements is empty, just return 0.
  if (empty(elements)) return 0;

  max = -1;

  # If same_type, then set the element type to the type of the first
  # element in elements.
  if (same_type)
  {
    local_var keys, element_type;

    keys = keys(elements);
    element_type = typeof(elements[keys[0]]);
  }

  foreach element (elements)
  {
    # If same_type, then make sure element is the right type or return
    # with error.
    if (same_type && typeof(element) != element_type)
    {
      err_print("maxlen(): arg 'same_type' set but elements not all of same type.");
      return -1;
    }

    if (len(element) > max) max = len(element);
  }

  return max;
}

##
# Checks if object is empty.
#
# @param  any object
#
# @return int TRUE if object is len == 0, FALSE otherwise, -1 on error
##
function empty(object)
{
  # Allow argument anonymously.
  if (isnull(object)) object = _FCT_ANON_ARGS[0];
  if (isnull(object))
  {
    err_print("empty(): missing required arg 'object'");
    return -1;
  }

  if (len(object) == 0) return TRUE;
  else return FALSE;
}

##
# Checks if object is empty or null.
#
# @param  any object
#
# @return int TRUE if isnull() or empty() return TRUE
#             FALSE otherwise
##
function empty_or_null(object)
{
  # Allow argument anonymously.
  if (isnull(object)) object = _FCT_ANON_ARGS[0];

  if (isnull(object) || empty(object)) return TRUE;
  else return FALSE;
}

##
# Wrapper function for egrep and eregmatch that returns matches on
# multi-line input.
#
# @param  string string to run regex against
# @param  string pattern regex pattern
# @param  int icase OPTIONAL passed to egrep and eregmatch
# @param  int max_matches OPTIONAL max number of matches that will be
#             returned
#
# @return list NULL if no matches.
#              single match if max_matches == 1
#              list of matches (as returned by eregmatch) otherwise
##
function multiline_eregmatch(string, pattern, icase, max_matches)
{
  local_var lines, index;
  local_var matches;

  # First 2 args are required.
  if (isnull(string))
  {
    err_print("multiline_eregmatch(): missing required arg 'string'");
    return NULL;
  }

  if (isnull(pattern))
  {
    err_print("multiline_eregmatch(): missing required arg 'pattern'");
    return NULL;
  }

  if (isnull(max_matches) || max_matches < 1) max_matches = 1;

  matches = make_list();
  index = 0;
  # Get all matching lines via egrep().
  # We split and re-join the string to allow for regex anchoring when dealing with multi-line buffers
  # pulled from the KB. This should not affect anything else.
  lines = split(egrep(string:join(split(string, sep:'\r\n', keep:FALSE), sep:'\n'), pattern:pattern, icase:icase));
  if (isnull(lines)) lines = make_list();

  while (len(matches) < len(lines) && len(matches) < max_matches)
  {
    matches[index] = pregmatch(string:lines[index], pattern:pattern, icase:icase);
    index++;
  }

  if (empty(matches)) return NULL;
  else if (max_matches == 1) return matches[0];
  else return matches;
}

##
# Splits path into head and tail, similar to os.split() in Python.
#
# @param  string path path to split
#
# @return list 2 element list containing head and tail. If string is
#              not a valid path, the string is returned in first
#              element and 2nd element is empty string.
##
function path_split(path)
{
  local_var pattern, match;
  local_var output;

  if (isnull(path)) path = _FCT_ANON_ARGS[0];

  if (isnull(path))
  {
    err_print("path_split(): missing required arg 'path'");
    return NULL;
  }

  pattern = "^(.*[\/\\])+(.*(\.\w+)?)?$";

  match = pregmatch(string:path, pattern:pattern);
  if (isnull(match)) return make_list(path, '');

  output = make_list(match[1]);
  if (!isnull(match[2])) output[1] = match[2];
  else output[1] = '';

  return output;
}

##
# Returns the parent directory of path, similar to os.dirname() in
# Python.
#
# @param  string path valid path (nix or Windows)
#
# @return string  parent directory of path or path itself
##
function dirname(path)
{
  local_var split_path;

  if (isnull(path)) path = _FCT_ANON_ARGS[0];

  if (isnull(path))
  {
    err_print("dirname(): missing required arg 'path'");
    return NULL;
  }

  split_path = path_split(path);

  return split_path[0];
}

global_var CPE_CLASS_APPLICATION = 'a';
global_var CPE_CLASS_HARDWARE = 'h';
global_var CPE_CLASS_OS = 'o';

##
# Stores product information to be reported in scan_info.nasl
#
# @param  string  product_name   product name
# @param  string  version        version string
# @param  string  cpe_base       CPE base string
# @param  string  cpe_class      CPE_CLASS_* (APPLICATION, HARDWARE, or OS)
# @param  bool    is_custom_cpe  Does an official CPE exist with cpe_base?
#
##

function register_unsupported_product(product_name, version, cpe_base, cpe_class,
                                      is_custom_cpe)
{
  local_var num_unsupported, cpe_prefix;

  if(isnull(cpe_class))
    cpe_class = CPE_CLASS_APPLICATION;

  if(cpe_class == CPE_CLASS_OS && defined_func("report_xml_tag"))
    report_xml_tag(tag:"operating-system-unsupported", value:"true");

  if(isnull(is_custom_cpe))
    is_custom_cpe = FALSE;

  if(isnull(product_name))
    err_print("register_unsupported_product(): missing required arg 'product_name'");

  if(isnull(version))
    version = "unknown";

  if(isnull(cpe_base))
    err_print("register_unsupported_product(): missing required arg 'base_path'");

  cpe_prefix = '';
  if(is_custom_cpe) cpe_prefix = 'x-';

  num_unsupported = get_kb_item("NumUnsupportedProducts");
  if(isnull(num_unsupported)) num_unsupported = 0;

  set_kb_item(name:"UnsupportedProducts/" + num_unsupported + "/product_name",
              value:product_name);

  set_kb_item(name:"UnsupportedProducts/" + num_unsupported + "/cpe_prefix",
              value:cpe_prefix);

  set_kb_item(name:"UnsupportedProducts/" + num_unsupported + "/cpe_class",
              value:cpe_class);

  set_kb_item(name:"UnsupportedProducts/" + num_unsupported + "/cpe_base",
              value:cpe_base);

  set_kb_item(name:"UnsupportedProducts/" + num_unsupported + "/version",
              value:version);

  num_unsupported++;
  replace_kb_item(name:"NumUnsupportedProducts", value:num_unsupported);
}

##
# Creates a properly formatted report item string
#
# @param array  report_items    name/value array to build report string
# @param list   ordered_fields  OPTIONAL list of report fields (keys in
#                               report_items) in order you want them
#                               reported
#
# @remark if specified, list of fields in ordered_fields must match
#         1-to-1 with keys in report_items
#
# @return string report items string
#
##
function report_items_str(report_items, ordered_fields)
{
  local_var key, max_len, report, rep_item;
  report = '';
  max_len = 0;

  if(isnull(report_items)) return NULL;
  if(typeof(report_items) != 'array') return NULL;

  if(!isnull(ordered_fields))
  {
    if(typeof(ordered_fields) != 'array') return NULL;
    if(max_index(ordered_fields) != max_index(keys(report_items)))
      return NULL;
  }

  if(max_index(keys(report_items)) == 0) return NULL;

  foreach key (keys(report_items))
    if(strlen(key) > max_len) max_len = strlen(key);

  if(isnull(ordered_fields))
  {
    foreach key (keys(report_items))
    {
      rep_item = report_items[key];
      if(isnull(rep_item)) return NULL;
      report += '\n  ' + key + crap(data:' ', length:max_len - strlen(key)) + ' : ' + rep_item;
    }
  }
  else
  {
    foreach key (ordered_fields)
    {
      rep_item = report_items[key];
      if(isnull(rep_item)) return NULL;
      report += '\n  ' + key + crap(data:' ', length:max_len - strlen(key)) + ' : ' + rep_item;
    }
  }

  return report + '\n';
}

##
# Fixup a string to make it csv compatable
#
# @param [data:string] the string to fix
#
# @return string fixed string
##
function format_for_csv(data)
{
  local_var ret;

  if (isnull(data) || strlen(data) < 1) return ' n/a ';

  ret = str_replace(string:data, find:'"', replace:'""');
  ret = str_replace(string:ret, find:'\r', replace:"\r");
  ret = str_replace(string:ret, find:'\n', replace:"\n");

  return ret;
}

##
# obtain the system name as it is reported in the UI
##
function set_system_name()
{
  local_var Host, HostID, myHostName;

  myHostName = get_kb_item("myHostName");
  if ( !isnull(myHostName) ) return myHostName;

  mutex_lock("query_report");
  Host = query_report("SELECT id FROM Host WHERE hostname = ?", get_host_ip() );
  mutex_unlock("query_report");

  if ( !isnull(Host) && !isnull(Host[0]) )
   HostID = Host[0]["id"];
  else
   HostID = NULL;

  if ( isnull(HostID) )
   myHostName = get_host_name();
  else
   myHostName = get_host_ip();

  replace_kb_item(name:"myHostName", value:myHostName);
  return myHostName;
}

##
# return the system name set by set_system_name()
#
# @return string on success | NULL on failure
##
function get_system_name()
{
  local_var name;

  name = get_kb_item("myHostName");

  if (isnull(name)) return "";

  return name;
}

##
# send in a string with an IP address and it will lstrip, rstrip the
# whitespace and validate the IP address is an IPv4 address and return
# cleaned version of the IP.
#
# @param [ip:string] the IP address the check
#
# @return NULL if check fails, string IPv4 address if passed
##
function validateIPv4Format(ip)
{
  # strip out all whitespace on left and right
  ip = ereg_replace(string:ip, replace:'', pattern:"^\s*");
  ip = ereg_replace(string:ip, replace:'', pattern:"\s*$");

  if (pregmatch(string:ip, pattern:"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"))
  {
    return ip;
  }
  else
  {
    return NULL;
  }
}

##
# Returns a list of ports the provided service was found on.
# Usage: port = get_service_port_list(svc:"smtp", default_port:25);
#
# @remark This should not fork since we are not using get_kb_item.
#
# @param svc A service name (SSH, Telnet, FTP, etc) (required)
# @param default Fall-back port number (22 for SSH, 23 for Telnet, etc) (optional).
# @param ipproto An IP protocol (optional).
# @param exit_on_fail Exit on a failure (optional).
#
# @return A list of port numbers for the requested service.
##
function get_service_port_list(svc, default, ipproto, exit_on_fail)
{
  var port_list, svc_ports;

  if(!svc && exit_on_fail) exit(0, "No service was provided to get_service_list.");

  if (!ipproto || ipproto == "tcp") port_list = get_kb_list("Services/" + svc);
  else port_list = get_kb_list("Services/"+ipproto+"/"+svc);

  if(port_list) svc_ports = make_list(port_list);
  else if(default) svc_ports = make_list(default);
  else svc_ports = NULL;

  if(!svc_ports && exit_on_fail) exit(0, "No ports were found for the " + svc + "service");
  else return svc_ports;
}

##
# Returns a sanitized string.
# Usage: sanitized = san_str(str:password);
#
# @param str A string to be sanitized.
#
# @return A sanitized string.
##
function san_str(str)
{
  var replace, ret;

  replace = crap(data:"*", length:strlen(str)-1);

  ret = ereg_replace(string:str, pattern:"\B.*", replace:replace);

  return ret;
}


##
# Return list of ot kb entries created by register_service
#
# @return list of ot protocol entries in KB or NULL if none exist
#
function ot_proto_list()
{
  return get_kb_list( KB_OT_PROTO + '/*' );
}

##
# Indicate if any (at least one) OT proto entry exist in KB
#
# @return TRUE if OT proto entry exist in KB
#         FALSE if absent, no known OT proto in KB
#
function has_ot_proto()
{
  # KB holds OT info, get all entries that indicate OT detected
  local_var services = ot_proto_list();
  # do any OT entries exist?
  if ( isnull(services) )
  {
    # no, OT entries not detected, let caller know
    return FALSE;
  }
  # OT entries detected, let caller know
  return TRUE;
}
