#TRUSTED 68ec03dde2e3676bec838a980fe5ceafe1cda7eae34f337d71ead5502b9dbc41ec7ec4055cec5757459388b6ce59675f3a522a47a5abd64beb1d855883ea1ea46c2e5ef8d8966e1a6b346ad48ea1fd9dc69b43bfc461b1546f1d406d6510ffcd947b82484036e27f66f705cee1153db1b5da1fb818dbe0e3083a7711c07c2754eb1296be9594e1d18c0b95ecf2495f3ac90c6133951603da2dc349ca3170707ea2644d3ac55fd9dd6e56cab2ed333ee39e11344b86af29300ce0d5c1c1a3a1a58bd8a0eadb06e44ccb27b0487c1ec486cad54d874bdbc252abd00de7b8b956fa9a124edc5c437707ac581226d09b8f5b6608010a9ac95f70cfec224be3f1d768e43eedd8072bbe284699c8966ded48b6aa763863853dbc4dd2d91bd7476e1b8d424a826edd41ec74188e73c3827744b0c851147880208cf4377707afdcb9169ea3deb915a251a0095caa47f11efb086ddb91aa098aabef708eb463e82bd7605fadb9fef6e52524cc6d6b4c450486cec2105f47004071aeb47ae4537843b72d40572865789b492ddd7f07bbecc868dacdb7b7315b01dad5811d6adc8e122b4fb587596d980b27777b6772fae4464265bf34681882430111726613928c4913454d8fddc89335ab3e593baac2b94acfa642cc4e9d2e6c939cc0fe67cb5122a97f60beb2aa50de50b8d3c4837388ac9c213b3180e0ddb62a0b5cf51aa24a6e1251ff
# -*- Fundamental -*-
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
#
# @NOGPL@
#
# http_misc_func.inc
# Revision: 1.40
#pragma static
include("global_settings_nlib.inc");
include("misc_func_nlib.inc");
include("obj_nlib.inc");

function get_http_banner(port, broken, exit_on_fail)
{
  local_var soc, sb, banner, req, body;
  
  if (! get_port_state(port))
  {
    if (exit_on_fail) exit(1, "Port "+port+" is closed.");
    return NULL;
  }
  if (! broken && get_kb_item("Services/www/" + port + "/broken") )
  {
    if (exit_on_fail) exit(1, "The web server on port "+port+" is broken.");
    return NULL;
  }
  
  sb = "www/real_banner/" + port;
  banner = get_kb_item(sb);
  if(banner) return(banner);
  
  sb = "www/banner/" + port;
  banner = get_kb_list(sb);
  if ( !isnull(banner) )
  {
    banner = make_list(banner);
    return banner[0];
  }

  soc = http_open_socket(port);
  if(!soc)
  {
    if (exit_on_fail) exit(1, "Connection to TCP port "+port+" failed.");
    return (NULL);
  }
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  banner = http_recv_headers2(socket:soc);
  #body = http_recv_body(socket:soc, headers: banner);
  http_close_socket(soc);
  if(banner)
	replace_kb_item(name: sb, value: banner);
  else if (exit_on_fail)
    exit(1, "The web server on port "+port+" did not answer.");

  return(banner);
}

# Rewritten & modified by WebRAY Network Security
function get_http_port(default, embedded, ignore_broken, dont_exit, dont_break, php, asp, no_xss)
{
  local_var	port, msg, to;

  port = get_kb_item("Services/www");
  if (! port) port = default;
  if (! get_port_state(port))
  {
    if (dont_exit) return NULL;
    exit(0, 'Port ' + port + ' is closed');
  }
  if (! embedded && get_kb_item("Services/www/" + port + "/embedded"))
  {
    if (dont_exit) return NULL;
    exit(0, 'The web server on port ' + port + ' is embedded.');
  }
  if (! ignore_broken && http_is_broken(port: port, dont_break: dont_break))
  {
    if (dont_exit) return NULL;
    exit(1, 'The web server on port ' + port + ' is broken.');
  }
  if (php && ! can_host_php(port: port))
  {
    msg = 'The web server on port '+port+' does not support PHP scripts.';
    debug_print(msg);
    if (dont_exit) return NULL;
    exit(0, msg);
  }
  if (asp && ! can_host_asp(port: port))
  {
    msg = 'The web server on port '+port+' does not support ASP scripts.';
    debug_print(msg);
    if (dont_exit) return NULL;
    exit(0, msg);
  }
  if (no_xss && get_kb_item("www/" + port + "/generic_xss"))
  {
    msg = 'The web server itself on port '+port+' is vulnerable to cross-site scripting (XSS).';
    debug_print(msg);
    if (dont_exit) return NULL;
    exit(0, msg);
  }

  to = get_kb_item('www/'+port+'/read_timeout');
  if (to > http_get_read_timeout()) http_set_read_timeout(to);
  http_reauthenticate_if_needed(port: port, save_cookies: 1);
  return port;
}

function declare_broken_web_server(port, reason)
{
  replace_kb_item(name: "Services/www/" +port+ "/broken", value: TRUE);
  if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Services/www/" +port+ "/working", value: TRUE);
  replace_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
  if (reason)
    replace_kb_item(name: "Services/www/" +port+ "/broken/reason", value: reason);
}

function http_is_broken(port, dont_break)
{
  local_var	starttime, endtime, delay, r, s, timeout;

  if (get_kb_item("Services/www/"+port +"/broken")) return 1;
  if (get_kb_item("Services/www/"+port+"/working")) return 0;
  if (dont_break) return 0;

  timeout = get_read_timeout();
  starttime = unixtime();
  r = http_send_recv3(port: port, method: 'GET', item: '/', version: 11, no_body: 1);

  if (isnull(r))
  {
    declare_broken_web_server(port: port, reason:
     "The web server failed to respond.");
    return 1;
  }

  endtime = unixtime();
  delay = endtime - starttime;
  if (delay > 2 * timeout)
  {
   declare_broken_web_server( port: port, reason:
     'The web server took '+delay+' seconds to read /');
   return 1;
  }

  if (r[0] =~ '^HTTP/[0-9.]+ 503 ')
  {
    declare_broken_web_server(port: port, reason:
      'The server answered with a 503 code (overloaded).');
    return 1;
  }

  if (r[0] =~ '^HTTP/[0-9.]+ +403 ' && delay >= timeout)
  {
    declare_broken_web_server(port: port, reason:
      'The server took '+delay+' seconds to send back a 403 code on /');
    return 1;
  }

  if ("HTTP" >!< r[0])
  {
    declare_broken_web_server(port: port, reason:
      'The server appears to speak HTTP/0.9 only.');
    return 1;
  }

  if (port == 5000 && r[0] =~ "^HTTP/[0-9.]+ +400 ")
  {
    declare_broken_web_server(port: port, reason:
      'The web server returned a 400 code on port 5000.');
    return 1;
  }

  set_kb_item(name: "Services/www/" +port+ "/working", value: TRUE);
    debug_print("http_is_broken(port: ", port, "): server is working", level: 2);
  return 0;
}

#
# That's for chunk-decoding
#
function __hex_value(num)
{
   if(num == "a")return(10);
   if(num == "b")return(11);
   if(num == "c")return(12);
   if(num == "d")return(13);
   if(num == "e")return(14);
   if(num == "f")return(15);
   return(int(num));
}

function hex2dec(xvalue)
{
 local_var ret, l, i, n, m;
  
 if(!xvalue)return(0);
 xvalue = tolower(xvalue);
 if ( '\r\n' >< xvalue )
 	l = strlen(xvalue) - 2;
 else if ( '\n' >< xvalue)
	l = strlen(xvalue) - 1;
 else   l = strlen(xvalue);

 ret = 0;
 m = 1;
 if ( l == 0 ) return 0;
 
 # Remove the trailing spaces
 while(l > 0 && xvalue[l - 1] == " " )l--;
 
 for(i=l;i>0;i--)
 {
  n = __hex_value(num:xvalue[i - 1]) * m;
  ret = ret + n;
  m = m * 16;
 }
 return int(ret);
}

function cgi_dirs()
{
 local_var kb;
 if ( get_kb_item("Settings/disable_cgi_scanning") ) return make_list();

 kb = get_kb_list("/tmp/cgibin");
 if(isnull(kb))kb = make_list("/cgi-bin", "/scripts", "");
 else kb = make_list(kb, "");
 
 return(kb); 
}

function can_host_php(port)
{
  local_var banner, banner_pat, sig;

  # nb: banners can sometimes be manipulated so always return TRUE if 
  #     we're being paranoid.
  if (report_paranoia > 1) return 1;

  if (get_kb_item("www/"+port+"/PHP")) return 1;

  banner = get_http_banner(port:port);
  if (! banner) return 0;	# Broken web server

  if (egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:banner, icase:1))
     return 1;

  banner_pat = "(aolserver|apache|Embedthis-(Appweb|http)|Mbedthis-AppWeb|Hiawatha v|IceWarp|iis|lighttpd|pi3web|Resin|thttpd|zeus|LiteSpeed)";
 if ( egrep(pattern:"^Server:.*"+banner_pat, string:banner, icase:1 ) )
		return 1;

# Try HMAP
 sig = get_kb_item("www/hmap/" + port + "/description");
  if (sig)
	{
    if (" PHP/" >< sig)
      return 1;
    if (egrep(pattern:banner_pat, string:sig, icase:1))
	return 1;
	return 0;
	}
# No HMAP signature
  if (egrep(string: banner, pattern: "^Server:", icase: 1))
    return 0;
  else
    return 1; # Unknown web server - might be able to host a PHP website
}

function can_host_asp(port)
{
  local_var banner, banner_pat, sig;

  # nb: banners can sometimes be manipulated so always return TRUE if 
  #     we're being paranoid.
  if (report_paranoia > 1) return 1;

  if (get_kb_item("www/"+port+"/ASP")) return 1;

  banner = get_http_banner(port:port);
  if (! banner) return 0;	 # Broken web server

  if (egrep(pattern:"^X-Powered-By:.*ASP\.NET", string:banner, icase:1))
    return 1;
 banner_pat = "(Baby Web Server|GoAhead-Webs|IIS|TembriaWebServer|UltiDev Cassini)";
 if ( egrep(pattern:"^Server:.*"+banner_pat, string:banner, icase:1 ) )
		return 1;

# Try HMAP
 sig = get_kb_item("www/hmap/" + port + "/description");
  if (sig)
	{
    if (egrep(pattern:banner_pat, string:sig, icase:1))
	return 1;
    else
	return 0;
	}
# No HMAP signature
  if (egrep(string: banner, pattern: "^Server:", icase: 1))
    return 0;
  else
  # Unknown server, might host ASP
    return 1;
}

function build_url(port, host, qs, username, password)
{
local_var	t, url, p, n;

if (qs =~ "^https?://") return qs;

t = get_port_transport(port);
p = "";
if (t > ENCAPS_IP)
{
 url = "https://";
 if (port != 443) p = ':' + port;
}
else
{
 url = "http://";
 if (port != 80) p = ':' + port;
}

if (strlen(host) > 0)
n = host;
else
{
    if (get_kb_item("DNS/invalid_hostname"))
      n = get_host_ip();
    else
    {
n = get_host_name();
      if (n =~ "^([0-9]+\.)+in-addr\.arpa$")
        n = get_host_ip();
    }
  }

  if (! isnull(username) || ! isnull(password))
  {
    url += username;
    if (! isnull(password))
      url += ":" + password;
    url += "@";
}
url += n + p;
  if (strlen(qs) > 0 && qs[0] == '/') url += qs;
  else url += '/' + qs;
return url;
}

function split_url(url)
{
  local_var	r, h, p, dp;

  r = pregmatch(string: url, pattern: "^(https?)://(([^:/]+)(:[^:/]*)?@)?([^:/]+)(:[0-9]+)?([?/].*)?$", icase: 1);
  if (! isnull(r))
  {
    p = tolower(r[1]);
    h["scheme"] = p;
    if (p == "http")
    {
      dp = 80; h["ssl"] = 0;
    }
    else
    {
      dp = 443; h["ssl"] = 1;
    }
    if (! isnull(r[2]))
    {
      h["user"] = r[3];
      if (! isnull(r[4])) h["password"] = substr(r[4], 1);
    }
    h["host"] = r[5];
    if (isnull(r[6]))
      h["port"] = dp;
    else
      h["port"] = int(substr(r[6], 1));
    h["page"] = r[7];
    return h;
  }
  r = pregmatch(string: url, pattern: "^mailto://([^/]+)$", icase: 1);
  if (! isnull(r))
  {
    h["scheme"] = "mailto";
    h["address"] = r[1];
    return h;
  }
  return NULL;
}

function normalize_url_path(url)
{
  local_var	old, base, qs, i, len;

  len = strlen(url);
  for (i = 0; i < len; i ++)
    if (url[i] == '?')
      break;
  if (i == 0) return url;
  if (i < len)
  {
    base = substr(url, 0, i - 1);
    qs = substr(url, i + 1);
    if (isnull(qs)) qs = "";
  }
  else
  {
    base = url;
    qs = NULL;
  }
  base = ereg_replace(string: base, pattern: "//+", replace: "/");
  base = ereg_replace(string: base, pattern: "^/(\.\./)+", replace: "/");
  repeat
  {
    old = base;
    base = ereg_replace(string: base, pattern: "/\./", replace: "/");
  }
  until (old == base);
  repeat
  {
    old = base;
    base = ereg_replace(string: base, pattern: "/([^/.][^/]*|\.[^./][^/]*)/\.\./", replace: "/");
  }
  until (old == base);
  base = ereg_replace(string: base, pattern: "/([^/.][^/]*|\.[^./][^/]*)/\.\.$", replace: "/");
  if (isnull(qs)) return base;
  return base + "?" + qs;
}

function apache_module_is_installed(module, port)
{
 local_var	b, r;

 if (get_kb_item('www/'+port+'/no_apache')) return 0;
 if (get_kb_item('www/'+port+'/no_full_apache_banner')) return -1;

 b = get_kb_item('www/'+port+'/apache_banner');
 if (isnull(b))
 {
   b = get_http_banner(port: port);
   if (isnull(b)) return 0;

   b = egrep(string: b, pattern: "^Server: +(IBM_HTTP_Server|Apache|(Oracle[0-9]+iAS/[0-9.]+ )?Oracle HTTP Server)");
   if (strlen(b) == 0)
   {
     set_kb_item(name: 'www/'+port+'/no_apache', value: TRUE);
     return 0;
   }

   r = chomp(b);
   b = strstr(r, "Apache/");
   if (isnull(b))
   {
     b = strstr(r, "Apache");
     if (isnull(b))
       b = r;
   }
   set_kb_item(name: 'www/'+port+'/apache_banner', value: b);
   # Very old banner included letters, but no list of modules
   if (! preg(string: b, pattern: '^Apache/[0-9.]+ \\(.*\\) [^ \t].*$'))
   {
     set_kb_item(name: 'www/'+port+'/no_full_apache_banner', value: TRUE);
     return -1;
   }
 }
 if (preg(string: b, pattern: ' '+module+'[/ ]'))
   return 1;
 else
   return 0;
}

function get_squid_banner(port)
{
  local_var	r, lines, pat, v;

  if (!get_port_state(port)) return NULL;
  r = http_get_cache(item:"/", port:port);
  if (isnull(r)) return NULL;

  pat = "([Ss]quid/[0-9]+\.[^ \)]+)";
  lines = egrep(pattern: pat, string: r);
  if (! lines) return NULL;

  foreach r (split(lines, keep:FALSE))
  {
    v = pregmatch(pattern: pat, string: r);
    if (!isnull(v)) return v[1];
  }
  return NULL;
}

#
# Return NULL if no Server header was found. Otherwise, returns the 
# first Server line (might be an empty string in pathological cases)
#
function http_server_header(port)
{
  local_var	b, lines, s;

  s = get_kb_item('www/'+port+'/server');
  if (! isnull(s)) return s;
  b = get_http_banner(port: port, broken: 1, exit_on_fail: 1);
  lines = egrep(string: b, pattern: "^Server:", icase: 1);
  if (! lines) return NULL;
  lines = split(lines, keep: 0);
  s = chomp(lines[0]);
  lines = NULL;
  s = ereg_replace(string: s, pattern: '^Server:[ \t]*', replace: '');
  replace_kb_item(name: 'www/'+port+'/server', value: s);
  return s;
}

####

global_var	global_patterns, headers_patterns, body_patterns, FP_pattern;

function find_pattern(string, pattern, code)
{
  if (isnull(code))
  {
    code = substr(pattern, 0, 2);
    pattern = substr(pattern, 3);
  }

  if (code == "ST:")
  {
    if (pattern >< string) return 1; else return 0;
  }
  if (code == "RE:")
  {
    return egrep(string: string, pattern: pattern);
  }
  if (code == "RI:")
  {
    return egrep(string: string, pattern: pattern, icase: 1);
  }
  if (code == "PA:")
  {
    return match(string: string, pattern: pattern);
  }
  if (code == "PI:")
  {
    return match(string: string, pattern: pattern, icase: 1);
  }
  err_print('find_pattern: pattern "', pattern, '" does not start with proper code\n');
  return egrep(string: string, pattern: pattern);
}

function extract_pattern_from_resp(string, response, pattern, code, dont_clean)
{
  local_var	lines, i, n, i0, i1, i2, rep, s;

  if (isnull(string))
    string = response[0] + response[1] + '\n' + response[2];

  if (pattern == "GL")
  {
    for (i = 0; global_patterns[i]; i ++)
    {
      rep = extract_pattern_from_resp(string: string, pattern: global_patterns[i], dont_clean: dont_clean);
      if (! isnull(rep)) return rep;      
    }
    return NULL;
  }

  if (pattern == "EX")
  {
    i = -1;
    while (1)
    {
      i ++; rep = NULL;
      if (! isnull(headers_patterns[i]))
      {
        rep = extract_pattern_from_resp(string: response[1], pattern: headers_patterns[i], dont_clean: dont_clean);
        if (isnull(rep)) continue;
      }
      if (! isnull(body_patterns[i]))
      {
        if ("<meta" >< body_patterns[i])
	  s = http_head_part(html: response[2]);
	else
	  s = response[2];
        rep = extract_pattern_from_resp(string: s, pattern: body_patterns[i], dont_clean: dont_clean);
        if (isnull(rep)) continue;
      }
      # if headers_patterns & body_patterns are NULL, we exit here
      return rep;
    }
    # NOTREACHED    
  }

  lines = split(string);
  n = max_index(lines);
  for (i = 0; i < n; i ++)
    if (find_pattern(string: lines[i], pattern: pattern, code: code))
    {
      if (isnull(FP_pattern) ||
      	  ! find_pattern(string: lines[i], pattern: FP_pattern, code: code))
      break;
    }
  if (i >= n) return NULL;
  rep = "";
  i0 = i;
  i1 = i - 2; i2 = i + 2;	# Change this if you want more or less context
  if (i1 < 0) i1 = 0;
  if (i2 >= n) i2 = n - 1;
  for (i = i1; i <= i2; i ++)
  {
    # Nul characters disrupt KB or output
    s = str_replace(string: lines[i], find: '\0', replace: '.');
    if (dont_clean)
      rep += s + '\n';
    else if (i == i0)
    {
      if (strlen(s) <= 432)	# 6 * 72
      rep += clean_string(s: s, dont_truncate: 1) + '\n';
    else
        rep += isolate_pattern(s: s, pat: pattern) + '\n';
    }
    else
      rep += clean_string(s: s) + '\n';
  }
  return rep;
}

function split_long_line(line)
{
  local_var	res, len, maxlen;

  res = '';
  while (1)
  {
    len = strlen(line);
    if (len <= 72) return res + line;
    res += substr(line, 0, 72-1) + '\n';
    line = substr(line, 72);
  }
  #NOTREACHED
}

function isolate_pattern(s, pat, maxlen)
{
  local_var	l, s1, s2, e1, e2, i, z;

  if (maxlen <= 0) maxlen = 72;

  s = chomp(s);
  s = ereg_replace(string: s, pattern: '^[ \t]+', replace: ''); 
  l = strlen(s);
  if (l <= maxlen) return s;

  l --;
  s1 = 0; s2 = l;
  while (s1 < s2 - 1)
  {
    i = (s1 + s2) / 2;
    z = substr(s, i);
    if (find_pattern( string: z, pattern: pat))
      s1 = i;
    else
      s2 = i;
  }
  e1 = s1 + 1; e2 = l;
  while (e1 < e2 - 1)
  {
    i = (e1 + e2) / 2;
    z = substr(s, s1, i);
    if (find_pattern( string: z, pattern: pat))
      e2 = i;
    else
      e1 = i;
  }
  if (e2 - s1 < maxlen)
  {
    z = maxlen - (e2 - s1); z /= 2;
    s1 -= z; e2 +=  z;
    if (s1 < 0)
    {
      e2 -= s1;
      s1 = 0;
    }
    if (e2 > l)
    {
      s1 -= (e2 - l);
      if (s1 < 0) s1 = 0;
      e2 = l;
    }
  }
  # 6 == strlen(' [...]')
  if (s1 < 6) s1 = 0;
  if (e2 > l - 6) e2 = l;
  s = substr(s, s1, e2);
  if (s1 > 0) s = '[...] ' + s;
  if (e2 < l) s += ' [...]';
  return s;
}

function clean_string(s, dont_truncate)
{
 local_var	l;

 s = chomp(s);
 s = ereg_replace(string: s, pattern: '^[ \t]+', replace: ''); 
 l = strlen(s);
 if (l <= 72) return s;
 if (dont_truncate)
   return split_long_line(line: s);
 else
 return substr(s, 0, 65) + " [...]";
}

function http_head_part(html)
{
  local_var	i1, i2, buf;

  if (strlen(html) == 0) return "";

  buf = tolower(html);
  i1 = stridx(buf, "<head>");
  if (i1 < 0) return "";

  i2 = stridx(buf, "</head>");
  if (i2 < i1) return "";

  return substr(html, i1, i2);
}

function beginning_of_response(resp, max_lines)
{
  local_var	txt, i, line;

  if (max_lines <= 0) max_lines = 10;
  i = 0;
  foreach line(split(resp, keep: 0))
  {
    txt += clean_string(s: line) + '\n';
    if (++ i  >= max_lines) return txt + '[...]\n';
  }
  return txt;
}

##
# This function test for generic path disclosures on HTTP responses.
# 
# @param item The item to request.
#
# @param port Port.
#
# @param method HTTP Method. e.g. "GET" or "POST"
#
# @param path_type Path type to look for.  
#    None (default) : looks for Windows and Unix paths
#    'windows' : Looks for only a Windows path 
#    'unix' : looks for only a Unix path
#
# @param filename: Filename portion to look for in path.
#    e.g. /var/www/html/filename
#    May only contain the following characters: 
#      alpha numeric, underscores, dashes, and dots
#
# @param add_headers: Specify additional HTTP headers.
#
# @follow_redirect: Number of times to follow redirect in response.
#
# @fetch404: If TRUE, fetch results even if code is 404.
#
# @param exit_on_fail: Exit with error on failure if TRUE.
#
# @return 1 if path disclosure found, 0 otherwise 
##
function test_generic_path_disclosure(item, port, method, path_type, filename, add_headers, follow_redirect, fetch404, exit_on_fail)
{
  local_var report_snip, txt, res, path, report, url;

  url = item;

  res = http_send_recv3(method: method, 
                        item: url,
                        port: port, 
                        add_headers: add_headers, 
                        follow_redirect: follow_redirect, 
                        exit_on_fail: exit_on_fail,
                        fetch404: fetch404); 

  if (res[0] =~ '^HTTP/1\\.[01] +30[1237] ' && fetch404)
    return 0;

  # make sure filename parameter is provided 
  if(isnull(filename) || filename == "")
  {
    if(exit_on_fail)
      exit(1, "Must provide a filename parameter.");

    return 0;
  }

  # check filename parameter, and error out if need be
  if(!egrep(pattern: "^[A-Za-z\.0-9_-]+$", string:filename))
  {
    if(exit_on_fail)
      exit(1, "Invalid characters in filename parameter.");

    return 0;
  }

  # escape any special regex characters
  str_replace(find:".", replace:"\.", string:filename);

  report_snip = NULL;
  path = NULL;

  if(path_type != 'unix') 
  {
    # Windows 
    # Example: "C:\inetpub\wwwroot\niet1982535136"
    # Valid filenames can't contain these characters: \/:*?"<>| 
    txt = extract_pattern_from_resp(pattern:'RE:(^|[^A-Za-z])([A-Za-z]:\\\\([^/:*?\"<>|\\\\]+\\\\)+)' + filename, response:res, dont_clean: TRUE);
    if (!isnull(txt)) 
    {
      report_snip = txt;
      item = pregmatch(pattern:'(^|[^A-Za-z])([A-Za-z]:\\\\([^/:*?\"<>|\\\\]+\\\\)+)' + filename, string:report_snip);
      path = item[2];      
    }
    # Windows with slashes other direction (e.g. c:/windows/...)
    txt = extract_pattern_from_resp(pattern:'RE:(^|[^A-Za-z])([A-Za-z]:/([^/:*?\"<>|\\\\]+/)+)' + filename, response:res, dont_clean: TRUE);
    if (!isnull(txt) && isnull(report_snip))
    {
      report_snip = txt;
      item = pregmatch(pattern:'(^|[^A-Za-z])([A-Za-z]:/([^/:*?\"<>|\\\\]+/)+)' + filename, string:report_snip);
      path = item[2];
    }
  }
  if(path_type != 'windows') 
  {
    # Unix
    # Example: "/var/www/html/niet9437234832"
    txt = extract_pattern_from_resp(pattern:'RE:(^|[^/]+)/(Library|var|etc|home|bin|etc|opt|private|usr)(/([^/<>: ]+/)+)' + filename, response:res, dont_clean: TRUE);
    if (!isnull(txt) && isnull(report_snip)) 
    {
      report_snip = txt;
      item = pregmatch(pattern:'(^|[^/]+)(/([^/<>: ]+/)+)' + filename, string:report_snip);
      path = item[2];
    }
  }

  # it should be impossible to reach this condition, but check just in case
  if(report_snip && isnull(path))
  {
    if(exit_on_fail)
      exit(1, "Unable to parse path from response.");
    return 0;
  }

  if(report_snip && !isnull(path))
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n  URL                 : ' + build_url(qs:url, port:port) +
        '\n  Path disclosed      : ' + path +
        '\n  Response snippet    : ' + 
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        report_snip + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

        security_warning(port:port, extra:report); 
    } 
    else security_warning(port:port);
    return 1;
  }
  return 0;
}

##
# Normalize an HTTP string such as the return value of http_get_cache()
# to the same format of the return value of http_send_recv3()
#
# @param  res HTTP response such as the return value from http_get_cache()
#
# @return list in the format of http_send_recv3() return value:
#           ret[0] = HTTP status
#           ret[1] = HTTP headers
#           ret[2] = HTTP body
#         NULL if an error occurred
## 
function http_normalize_res(res)
{
  local_var status, headers, body, status_headers;

  if (isnull(res) || len(res) == 0)
    return NULL;

  # http_send_recv3() return value - already desired list format
  if (typeof(res) == 'array' && max_index(res) == 3)
    return res;

  # http_get_cache() return value - HTTP response in a string 
  if (typeof(res) == 'string' || typeof(res) == 'data')
  {
    if (res !~ "^HTTP") return NULL;

    # Body
    body = strstr(res, '\r\n\r\n');
    if (isnull(body)) return NULL;
    body -= '\r\n\r\n';

    # Status
    status_headers = res - body;
    status = status_headers - strstr(status_headers, '\r\n');
    status += '\r\n';

    # Headers
    headers = status_headers - status;

    return [status, headers, body];
  }

  return NULL;
}
