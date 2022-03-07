#TRUSTED 9ea6d97ac00b2bbf3b2c7963deade54de4d1e05cac44d7d56350840d52fc217f3fef4516f4146468b1c99510b9263fdb4f7dd6d98c98b542dcea6a784f4f4aced8985e54028675e86f20b76d4232c56375887c6737ae88d734745fcd9e692e2ca7a453d0dfa0c8f1876944ac374246508dcdca111e2c2f044041e3d59b9fc5c56fed9a85e62a29818004fb5707cce179bfb0edc14c798eaadec9e223b39dd486260cefddfd290d5ac214520df4907a2a47b1d7001ec779e74effe8702bd6513faad5c0d96ea687e3fdcc2cedcaadc205b36297fc10bdc118f7f6f6e3d21efa4de24f0b8b59ff15031f8628bc24a70e8c41025330e8c3fd60d5a3db709292b25e333bfe822db78e2282e2e867e02399836f0f5465a306038f8156374fea6fe5200883c9e4ffa6cb23d9dc87172b5cd0ce54eda30bc3f80d0cac2c4e7eceaf2b27a4f457da9be2ccf19a323e37ca8a59e16a9587c6f95a29ca017368166ffcf44ac8e7270cc02918990af9fa44574f1adda317cfc1bf1d66e125e669ae2439f49fb2a9a34aa0b408c109f1ce3ea716ab31bbb7b0e370a584d66150860790aec196eaa7480b4d70019cec2621ab7eebb21a955d81192726d5a624dc2bb99b42a4ccc02a5f9860123f7bfa2d69bbe2aa6bee3cd8abce7d20e3f702a5c1c2aeba46eb50fe240b5634db7edbd75128c2c8f5ba0ab154d7cf67f1edc3296c27d0872a39
# -*- Fundamental -*-
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# http_cookie_jar.inc
# Revision: 1.18
#

# MA 2009-02-26
# RFC 2109 and 2965 say that "attributes" and "domains" are case-insensitive.
# It appears that Firefox does not handle case-insensitive attributes 
# (e.g. it is possible to set "PHPSESSID" and "PHPSESSid") and that converting 
# names to lower case breaks some web applications.

# You need to include global_settings.inc and misc_func.inc
#pragma static
include("global_settings_nlib.inc");

global_var CookieJar_value, CookieJar_version, CookieJar_expires,
           CookieJar_comment, CookieJar_secure, CookieJar_httponly,
           CookieJar_domain, CookieJar_port,
           CookieJar_is_disabled, CookieJar_autosave;
# Max-Age is not fully supported yet

global_var __cookies_style;
global_var HTTP_COOKIES_PLAIN   = 0;
global_var HTTP_COOKIES_RFC2109 = 2109;
global_var HTTP_COOKIES_RFC2965 = 2965;


function get_http_cookies_names(name_regex, value_regex, secure, hostname, port, path, max_nb)
{
  local_var	l, i, k, v, nam, pat;

  if (CookieJar_is_disabled) return NULL;
  l = make_list();

  foreach k (keys(CookieJar_value))
  {
    v = split(k, sep: '=', keep: 0);
    nam = v[0]; pat = v[1];
    if (! isnull(name_regex) && ! preg(string: nam, pattern: name_regex)) continue;
    if (! isnull(hostname) && ! isnull(CookieJar_domain[k]) &&
        ! match(string: hostname, pattern: '*'+ CookieJar_domain[k], icase: 1)) continue;
    if (! isnull(value_regex) && ! preg(string: CookieJar_value[k], pattern: value_regex)) continue;
    if (! isnull(path) && path != pat)
    {
      if (match(string: pat, pattern: "*/"))	
      {
        if (! match(string: path, pattern: pat + '*')) continue;
      }
      else
      {
        if (! match(string: path, pattern: pat + '/*')) continue;
      }
    }
    if (! isnull(port) && ! isnull(CookieJar_port[k]) && 
        port != CookieJar_port[k]) continue;
    # Warning! The logic with "secure" is slightly different
    if (secure && ! CookieJar_secure[k]) continue;

    l[nam] = 1;
    if (! isnull(max_nb) && -- max_nb <= 0) break;
  }
  return keys(l);
}

function replace_http_cookies(name_re, port, hostname, path, secure, old_value, old_value_re, new_value)
{
  local_var	k, v, nam, pat, n;

  if (CookieJar_is_disabled) return NULL;
  n = 0;
  foreach k (keys(CookieJar_value))
  {
    if (! isnull(hostname) && ! isnull(CookieJar_domain[k]) &&
        ! match(string: hostname, pattern: '*'+CookieJar_domain[k], icase:1)) continue;
    if (! isnull(port) && ! isnull(CookieJar_port[k]) && 
        port != CookieJar_port[k]) continue;
    if (! isnull(old_value) && old_value != CookieJar_value[k]) continue;
    if (! isnull(old_value_re) && ! preg(string: CookieJar_value[k], pattern: old_value_re)) continue;
    # Warning! The logic with "secure" is slightly different
    if (secure && ! CookieJar_secure[k]) continue;

    v = split(k, sep: '=', keep: 0);
    nam = v[0]; pat = v[1];
    if (! isnull(name_re) && ! preg(string: nam, pattern: name_re)) continue;
    if (! isnull(path) && path != pat)
    {
      if (match(string: pat, pattern: "*/"))	
      {
        if (! match(string: path, pattern: pat + '*')) continue;
      }
      else
      {
        if (! match(string: path, pattern: pat + '/*')) continue;
      }
    }
    CookieJar_value[k] = new_value;
    n ++;
  }
  return n;
}

function get_http_cookie_keys(name_re, port, hostname, path, secure)
{
  local_var	k, v, nam, pat, l;

  if (CookieJar_is_disabled || isnull(name_re)) return NULL;

  l = make_list();
  foreach k (keys(CookieJar_value))
  {
    v = split(k, sep: '=', keep: 0);
    nam = v[0]; pat = v[1];
    if (! preg(string: nam, pattern: name_re)) continue;
    if (! isnull(hostname) && ! isnull(CookieJar_domain[k]) &&
        ! match(string: hostname, pattern: '*'+CookieJar_domain[k], icase: 1)) continue;
    if (! isnull(path) && path != pat)
    {
      if (match(string: pat, pattern: "*/"))	
      {
        if (! match(string: path, pattern: pat + '*')) continue;
      }
      else
      {
        if (! match(string: path, pattern: pat + '/*')) continue;
      }
    }
    if (! isnull(port) && ! isnull(CookieJar_port[k]) && 
        port != CookieJar_port[k]) continue;
    # Warning! The logic with "secure" is slightly different
    if (secure && ! CookieJar_secure[k]) continue;
    l[k] = 1;
  }
  return keys(l);
}

function get_http_cookie_from_key()
{
 local_var	k, h, v;

 k = _FCT_ANON_ARGS[0];
 if (isnull(k))
 {
   err_print('get_http_cookie_from_key: missing argument!\n');
   return NULL;
 }
 v = split(k, sep: '=', keep: 0);
 if (max_index(v) != 2)
 {
   err_print('get_http_cookie_from_key: invalid key ', k);
   return NULL;
 }
 if (isnull(CookieJar_value[k]))
 {
   debug_print('get_http_cookie_from_key: inexistant cookie ', k);
   return NULL;	# undefined cookie
 }
 h = make_array();
 h["name"] = v[0]; 
 h["path"] = v[1];
 h["value"] = CookieJar_value[k];
 h["domain"] = CookieJar_domain[k];
 h["version"] = CookieJar_version[k];
 h["expires"] = CookieJar_expires[k];
 h["comment"] = CookieJar_comment[k];
 h["secure"] = CookieJar_secure[k];
 h["httponly"] = CookieJar_httponly[k];
 h["port"] = CookieJar_port[k];
 return h;
}

function set_http_cookie_from_hash()
{
 local_var	k, h;

 h = _FCT_ANON_ARGS[0];
 if (isnull(h))
 {
   err_print('set_http_cookie_from_hash: missing argument!\n');
   return NULL;
 }
 if (strlen(h["name"]) == 0 || strlen(h["path"]) == 0)
 {
   err_print('set_http_cookie_from_hash: name or path is missing!\n');
   return NULL;
 }
 k = h["name"] + '=' + h["path"];
 CookieJar_value[k] = h["value"];
 CookieJar_domain[k] = h["domain"];
 CookieJar_version[k] = h["version"];
 CookieJar_expires[k] = h["expires"];
 CookieJar_comment[k] = h["comment"];
 CookieJar_secure[k] = h["secure"];
 CookieJar_httponly[k] = h["httponly"];
 CookieJar_port[k] = h["port"];
 return k;
}

function clear_cookiejar()
{
  CookieJar_value = make_array();
  CookieJar_version = make_array();
  CookieJar_expires = make_array();
  CookieJar_comment = make_array();
  CookieJar_domain = make_array();
  CookieJar_secure = make_array();
  CookieJar_httponly = make_array();
  CookieJar_port = make_array();
}

function init_cookiejar()
{
  clear_cookiejar();
  load_cookiejar(jar: "FormAuth");
}

function erase_cookie()
{
  local_var	k, key;
  key = _FCT_ANON_ARGS[0];
  CookieJar_value[key] = NULL;
  CookieJar_version[key] = NULL;
  CookieJar_expires[key] = NULL;
  CookieJar_comment[key] = NULL;
  CookieJar_domain[key] = NULL;
  if (strlen(CookieJar_autosave) > 0)
   if (defined_func("rm_kb_item"))
     foreach k (make_list("value", "version", "expires", "comment", "secure", "domain"))
       rm_kb_item(name: "Cookies/"+CookieJar_autosave+"/"+hexstr(k)+"/"+key);
}

function erase_http_cookie(key, name, path)
{
  if (isnull(key))
  {
    if (isnull(name))
    {
      err_print("erase_http_cookie: either key or name must be set!\n");
      return NULL;
    }
    if (! path) path = "/";
    key = name + '=' + path;
  }
  else
  {
    if (! isnull(name))
      err_print("erase_http_cookie: key (", key, ") and name (", name, ") cannot be both set! Ignoring name.\n");
  }
  erase_cookie(key);
}

function set_http_cookie(key, name, path, value, domain, secure, version)
{
  if (isnull(key))
  {
    if (isnull(name))
    {
      err_print("set_http_cookie: either key or name must be set!\n");
      return NULL;
    }
    if (! path) path = "/";
    key = name + '=' + path;
  }
  else
  {
    if (! isnull(name))
      err_print("set_http_cookie: key (", key, ") and name (", name, ") cannot be both set! Ignoring name.\n");
  }
  CookieJar_value[key] = value;
  if (isnull(version)) version = 1;
  CookieJar_version[key] = version;
  CookieJar_domain[key] = domain;
  # CookieJar_expires[key] = NULL;
  # CookieJar_comment[key] = NULL;
  if (strlen(CookieJar_autosave) > 0)
    store_1_cookie(key: key, jar: CookieJar_autosave);
}

function get_any_http_cookie(name)
{
  local_var	k, v, found_p;

  foreach k (keys(CookieJar_value))
  if (! isnull(CookieJar_value[k]))
  {
    v = split(k, sep: '=', keep: 0);
    if (v[0] == name)
    {
      if (isnull(found_p) || strlen(found_p) > strlen(v[1]))
        found_p = v[1];
    }
  }
  if (isnull(found_p))
    return NULL;
  else
    return CookieJar_value[name + '=' + found_p];
}


function get_http_cookie(name, path)
{
  local_var	key, path2;

  if (strlen(path) == 0) return get_any_http_cookie(name: name);

  if (path[0] != "/")
  {
    err_print('get_http_cookie: path does not start with slash: ', path, '\n');
    path = '/' + path;
  }
  for ( path2 = path; strlen(path2) > 0; 
      	path2 = ereg_replace(string: path2, pattern: "^(.*)/[^/]*", replace: "\1"))
  {
    key = name + '=' + path2;
    if (! isnull(CookieJar_value[key]))  return CookieJar_value[key];
  }
  return NULL;
}


function parse_setcookie_header(header)
{
  local_var	v, name, key, value, path, fields;

  if (CookieJar_is_disabled) return 0;
  if (isnull(CookieJar_value)) init_cookiejar();
  header = chomp(header);
  if (match(string: header, pattern: "Set-Cookie:*", icase: 1))
  {
    header = substr(header, 11);
  }
  else if (match(string: header, pattern: "Set-Cookie2:*", icase: 1))
  {
    debug_print(level: 2, "parse_setcookie_header: Set-Cookie2 is not fully supported\n");
    header = substr(header, 12);
  }
  if (strlen(header) == 0)
  {
    debug_print('Empty Set-Cookie header\n');
    return 0;
  }

  while (strlen(header) > 0)
  {
    v = pregmatch(string: header, icase: 1,
    # MA 2008-12-05: we used to have [^;]+ for the value, as the RFC does not 
    # allow an empty value after =, but some broken servers send such things.
pattern: '^ *(([^$ =,;]+) ?= ?([^;]*))((; *(Secure|HttpOnly|(Max-Age|version) ?= ?[0-9]+|(expires|comment|path|domain) ?= ?[^;=]+|(Port|Comment-URL) ?= ?"[^"+"]| +))*)([,;] *(.*))?$');
    if (isnull(v))
    {
      debug_print('Cannot parse cookie header: ', header);
      return 0;
    }
    name = v[2];
    value = v[3];
    fields = v[4];
    header = v[11];

    fields += "; ";

    v = pregmatch(string: fields, icase: 1, pattern: "; *path ?= ?([^;]+) *;");
    if (isnull(v))
      path = "/";
    else
      path = v[1];
    # Domain should also be part of the key
    key = name + '=' + path;
    CookieJar_value[key] = value;

    v = pregmatch(string: fields, icase: 1, pattern: "; *Max-Age ?= ?([0-9]+) *;");
    if (! isnull(v) && int(v[1]) == 0)
    {
      erase_cookie(key);
      continue;
    }

    v = pregmatch(string: fields, icase: 1, pattern: "; *Secure *;");
    CookieJar_secure[key] = ! isnull(v);

    v = pregmatch(string: fields, icase: 1, pattern: "; *HttpOnly *;");
    CookieJar_httponly[key] = ! isnull(v);

    v = pregmatch(string: fields, icase: 1, pattern: "; *version ?= ?([0-9]+) *;");
    if (isnull(v))
      CookieJar_version[key] = 1;
    else
      CookieJar_version[key] = int(v[1]);

    v = pregmatch(string: fields, icase: 1, pattern: "; *expires ?= ?([^;]+) *;");
    if (isnull(v))
      CookieJar_expires[key] = NULL;
    else
      CookieJar_expires[key] = v[1];

    v = pregmatch(string: fields, icase: 1, pattern: "; *Comment ?= ?([^;]+) *;");
    if (isnull(v))
      CookieJar_comment[key] = NULL;
    else
      CookieJar_comment[key] = v[1];

    v = pregmatch(string: fields, icase: 1, pattern: "; *domain ?= ?([^;]+) *;");
    if (isnull(v))
      CookieJar_domain[key] = NULL;
    else
      CookieJar_domain[key] = v[1];
    if (strlen(CookieJar_autosave) > 0)
      store_1_cookie(key: key, jar: CookieJar_autosave);
  }
  return 1;
}

# Note: we do not have to keep a jar for each server.
# If a cooky is restricted to some port, this should be done with Set-Cookie2
# We do not fully support that...
function store_cookiejar()
{
  local_var	k;
  if (isnull(CookieJar_value)) return;
  foreach k (keys(CookieJar_value))
     store_1_cookie(key: k, jar: _FCT_ANON_ARGS[0]);
}

function store_1_cookie(key, jar)
{
  local_var	val, kbkey;

  kbkey = hexstr(key);
  if (isnull(jar)) jar = "Generic";
  val = CookieJar_value[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/value/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/value/"+kbkey);

  val = CookieJar_version[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/version/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/version/"+kbkey);

  val = CookieJar_expires[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/expires/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/expires/"+kbkey);

  val = CookieJar_comment[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/comment/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/comment/"+kbkey);

  val = CookieJar_secure[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/secure/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/secure/"+kbkey);

  val = CookieJar_httponly[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/httponly/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/httponly/"+kbkey);

  val = CookieJar_domain[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/domain/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/domain/"+kbkey);
}

function load_cookiejar(jar)
{
  local_var	l, kbi, k, v, trailer, k2;

  if (isnull(jar)) jar = "Generic";
  l = get_kb_list("Cookies/"+jar+"/value/*");
  if (isnull(l)) return;

  trailer = "Cookies/" + jar + "/value/";

  foreach kbi (keys(l))
  {
    k = kbi - trailer;
    k2 = hex2raw(s: k);
    CookieJar_value[k2] = l[kbi];
    CookieJar_version[k2] = get_kb_item("Cookies/"+jar+"/version/"+k);
    CookieJar_expires[k2] = get_kb_item("Cookies/"+jar+"/expires/"+k);
    CookieJar_comment[k2] = get_kb_item("Cookies/"+jar+"/comment/"+k);
    CookieJar_secure[k2] = get_kb_item("Cookies/"+jar+"/secure/"+k);
    CookieJar_httponly[k2] = get_kb_item("Cookies/"+jar+"/httponly/"+k);
    CookieJar_domain[k2] = get_kb_item("Cookies/"+jar+"/domain/"+k);
  }
}

function http_uri_is_subpath(uri, path)
{
  local_var	l1, l2;
  if (path == "/" || uri == path) return 1;

  if (! match(string: path, pattern: "*/")) path += "/";
  l1 = strlen(uri); l2 = strlen(path);
  # TBD: eliminate consecutive / in URI?
  if (l2 > l1) return 0;
  return substr(uri, 0, l2-1) == substr(path, 0, l2 - 1);
}


function mk_cookie_header(item)
{
  local_var	buf, k, name, path, i;
  local_var	cookies, j;
  buf = "";

  if (CookieJar_is_disabled) return NULL;
  if (isnull(CookieJar_value)) init_cookiejar();
  cookies = sort(keys(CookieJar_value));
  # RFC2109 says that the "most precise" cookies must come first
  for (j = max_index(cookies) - 1; j >= 0; j --)
  {
    k = cookies[j];
    i = stridx(k, '=');
    if (i <= 0) continue;	# Bug?
    # Erased cookie
    if (isnull(CookieJar_value[k]) && isnull(CookieJar_version[k])) continue;
    name = substr(k, 0, i - 1);
    path = substr(k, i + 1);
    if (! http_uri_is_subpath(uri: item, path: path)) continue;
    if (CookieJar_version[k] != 1)
    {
      debug_print( "mk_cookie_header: unhandled version ", CookieJar_version[k],
      		   " for cookie ", k);
      continue;
    }

    if (buf != "") buf += "; ";
    if (__cookies_style == HTTP_COOKIES_PLAIN)
    {
      buf = buf + name + "=" + CookieJar_value[k];
    }
    else
    {
      buf += name + "=" + CookieJar_value[k];
      buf += "; $Path=" + path;
      # RFC 2965  (Set-Cookie2)
      if (__cookies_style == HTTP_COOKIES_RFC2965)
      {
        if (CookieJar_domain[k] != "")
          buf += "; $Domain=" + CookieJar_domain[k];
        if (CookieJar_port[k] != "")
          buf += "; $Port=" + CookieJar_port[k];
      }
    }
  }
  if (strlen(buf) <= 0) return NULL;
  if (__cookies_style > HTTP_COOKIES_PLAIN)
    buf = '$Version="1"; ' + buf;
  return buf;
}

function dump_cookiejar()
{
  local_var	k, v, l;

  if (isnull(CookieJar_value)) return;
  foreach k (keys(CookieJar_value))
  {
    v = split(k, sep: '=', keep: 0);
    l = v[0] + '=' + CookieJar_value[k] + '; path=' + v[1];

    if (CookieJar_domain[k]) l += '; domain=' + CookieJar_domain[k];
    if (CookieJar_port[k]) l += '; port=' + CookieJar_port[k];
    if (CookieJar_expires[k]) l += '; port=' + CookieJar_expires[k];
    if (CookieJar_secure[k]) l += '; secure';
    if (CookieJar_httponly[k]) l += '; HttpOnly';
    debug_print( l, '\n');
  }
}

function disable_cookiejar()
{
  CookieJar_is_disabled = 1;
}

function enable_cookiejar()
{
  CookieJar_is_disabled = 0;
}

# The "FormAuth" cookie jar is always saved at the beginning of a script, 
# if it re-authenticates. See http_login.inc
function enable_cookiejar_autosave(jar)
{
  if (strlen(jar) == 0) jar = "Generic";
  CookieJar_autosave = jar;
}

function disable_cookiejar_autosave()
{
  CookieJar_autosave = "";
}

function http_cookies_style(style)
{
  local_var	old;
  old = __cookies_style;
  __cookies_style = style;
  return old;
}
