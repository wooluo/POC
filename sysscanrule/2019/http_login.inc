#TRUSTED 1c85105321c7f3177b41bd61101048572ad66fc0c75d8c1db565660488d5c58c02180cb2e9e3c637fbafe9037972d203f23bf61428bd0c8c82ee3de634d6dd9731387306021859b382ef7473f795507db345e6121f37888f29192162c60ece8c91568c11dd12edc847dd6a7799e5b0de0a0c02810c8fab4353d468d8cd9efdc2c0301c9453b390b8068add8fb7f251af8e48a948068adc1ebfdc368c6a3a20212c14780e78c565df6d3971fb376494f0796580375b8cecbad58d248fdfb9229dab9db3c96fdf4b1ff459fd7c60c2670c529ea084c18cfd8f706033334089ecb74a66be8ca2f22e561d1b3ef7a852e82fa9e9b2603578cf56cecf0cba38b94413cbe50a6e1e4ae8a2e7846efe5aff814ab78dd49ea0a6d464e2c7b767d8f14c47b537f393879139e7c23905915731e250096df2c9a724053317e492f84c8cc8179e832365c26cccedc47b1a1eb2670071f190ce6a3c2897bdfcd47662e9dd595d8d4477fa8fce8e4ab16a265099021171d287ed65616ddd21666caaeb4d752f47ac83f0ff3cae876383de20c3cecacb6b0f9b56962925bb760516f3e566443955814c97f52befcda2ee34f87dbff13dbecf3741f724d68690e0d7c36ebdcf77d43029f3d9414baf66b37509d94ae833e6fe89c28d95f6ff955dc2b97d6472a8a0015f94e7f87c56744519f780ee2a2ec99b2b5cb416d692ef97d6109ee7bb58b8
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
# http_login.inc
# Revision: 1.10
#pragma static
include("global_settings_nlib.inc");
include("misc_func_nlib.inc");
include("obj_nlib.inc");

global_var CookieJar_is_disabled;
global_var HttpLogin_reauthentication_OK, HttpLogin_reauthentication_KO;

function http_check_authentication(port, check_page, regex, re_invert, re_headers, re_icase, follow_redirect)
{
  local_var r, s, flag;

  if (strlen(check_page) == 0 || strlen(regex) == 0) return "";

  r = http_send_recv3(method:"GET", item: check_page, port: port, follow_redirect: follow_redirect);
  if (isnull(r))
  {
    return "request failed: GET " + check_page;
  }
  if (re_headers)
    s = egrep(string: r[0]+r[1], pattern: regex, icase: re_icase);
  else
    s = egrep(string: r[2], pattern: regex, icase: re_icase);
  flag = (strlen(s) > 0);
  if (flag)
    debug_print(level: 3, 'http_check_authentication extracted pattern: ', chomp(s));
  if (re_invert) flag = ! flag;
  if (! flag)
  {
    if (report_verbosity > 1)
      return "post-authentication test failed" + '.\nThe web server answered :\n\n' + r[0] + r[1] + '\n' + r[2];
    else
      return "post-authentication test failed";
  }
  return "OK";
}

# This function returns an empty string for "maybe", "OK" if authentication 
# succeeded (the control page could be check). Any other string is an error 
# message.
function http_form_login(port, page, form, fields, follow_redirect, 
	 		 save_cookies, check_page, regex, re_invert,
			 re_headers, re_icase, method)
{
  local_var	r, trp, h, e;

  h = make_array();
  e = "";

  if (page)
  {
    r = http_send_recv3(port: port, item: page, method: 'GET', follow_redirect: follow_redirect);
    if (isnull(r))
    {
      debug_print("Broken connection on port ", port, " after GET ", page);
      return "request failed: GET " + page;
    }

    trp = get_port_transport(port);
    h["Referer"] = build_url(port: port, qs: page);
  }

  if (! method) method = "POST";

  if (method == "POST")
  {
  h["Content-Type"] = "application/x-www-form-urlencoded";
  r = http_send_recv3( port: port, method: 'POST', 
      		       follow_redirect: follow_redirect,
      		       add_headers: h, 
    		       item: form, data: fields);
  }
  else
  {
    r = http_send_recv3( port: port, method: 'GET', 
      		       follow_redirect: follow_redirect,
    		       item: form + "?" + fields);
  }
  if (isnull(r))
  {
    debug_print("Broken connection on port ", port, " after ", method, " ", form);
    return "request failed: " + method + " " + form;
  }

  # Failed - permission denied or bad gateway or whatever
  # This happens sometimes when we follow redirections, but we might be 
  # authenticated anyway.
  if (r[0] =~ "^HTTP/[01.]+ +[45][0-9][0-9] ")
  {
    debug_print("Permission denied: code=", r[0]);
    e =  "Permission denied or other HTTP error on "+method+" request";
  }
  # All other codes are considered as OK. We might get a 30x code too!

  r = http_check_authentication(port: port, check_page: check_page, regex: regex, re_invert: re_invert, re_headers: re_headers, re_icase: re_icase, follow_redirect: follow_redirect);

  if (r == "")
  {
    # We could not check if we are authenticated but we got an error first. 
    # Let's return it.
    if (e != "") return e;
  } else if (r != "OK")	# Error
    return r;

  # Here, we are sure that we are authenticated (OK) 
  # or nothing proves that we are not.
  if (! CookieJar_is_disabled && save_cookies) store_cookiejar("FormAuth");
  return r;
}


function http_login_take_lock(port, now, delay)
{
  local_var	k, t, v;


  k = "/tmp/http_login/"+port+"/lock";
  t = get_kb_item(k);
  if (t)
  {
    v = split(t, sep:'-', keep: 0);
    t = now - int(v[0]);
    if (t > delay || t < 0)
    {
      debug_print("http_login_take_lock: old lock (", t, " s ago) deleted (port=", port, ")");
      rm_kb_item(name:k);
    }
    else
    {
      debug_print(level: 2, "http_login_take_lock: lock taken ", t, " s ago");
      return 0;
    }
  }
  v = now + '-' + rand();
  replace_kb_item(name:k, value: v);

  if (get_kb_item(k) != v)
  {
    debug_print("http_login_take_lock: lock stolen");
    return 0;
  }
  return 1;
}

function http_login_release_lock()
{
  local_var	k, port;
  port = _FCT_ANON_ARGS[0];
  k = "/tmp/http_login/"+port+"/lock";
  rm_kb_item(name: k); 
  return 1;
}


# This function should only be called if a lock has been taken
function http_login_incr_count(port, kb)
{
  local_var	k, n;

  k = "www/"+port+"/"+kb;
    n = get_kb_item(k);
    n ++;
    replace_kb_item(name: k, value: n);
  }

function http_reauthenticate_if_needed(port, save_cookies)
{
  local_var	page, form, fields, time, e, delay, now;
  local_var	cp, re, iv, hd, ic, fr, i, mt;

  cp = get_kb_item("www/"+port+"/check_page");
  re = get_kb_item("www/"+port+"/check_regex");
  iv = get_kb_item("www/"+port+"/regex_invert");
  hd = get_kb_item("www/"+port+"/regex_headers");
  ic = get_kb_item("www/"+port+"/regex_icase");
  fr = get_kb_item("www/"+port+"/login_follow_30x");

  e = http_check_authentication(port: port, check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic, follow_redirect: fr);
  if (e == "OK") return;

  # Ideally, we should take a mutex here, but the functions are privileged
  # and we do not want to sign all web scripts.

  if (e != "")		# use a tiny delay if we are disconnected
    delay = get_read_timeout();
  else
    delay = get_kb_item("www/"+port+"/login_delay");
  if (delay <= 0) return;

    time = get_kb_item("www/"+port+"/login_time");
  now = unixtime();
  if (time + delay > now)
    {
    debug_print(level: 2, 'Will not try to re-authenticate on port ', port, ' before ', time + delay - now, ' seconds\n');
      return;
    }

  if (! http_login_take_lock(port: port, now: now, delay: delay))
  {
    # Try to reload the cookie jar, in case another plugin updated it
    if (e != "") sleep(get_read_timeout());
    load_cookiejar(jar:"FormAuth");
    return;
  }

  page = get_kb_item("www/"+port+"/login_page");
  form = get_kb_item("www/"+port+"/login_form");
  fields = get_kb_item("www/"+port+"/login_fields");
  mt = get_kb_item("www/"+port+"/login_meth");

  e = http_form_login(port: port, page: page, form: form, fields: fields,
    save_cookies: save_cookies, method: mt, 
        check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic);
  if (e == "OK")
  {
    replace_kb_item( name: "www/"+port+"/"+SCRIPT_NAME+"/auth_OK", 
    		     value: ++ HttpLogin_reauthentication_OK);
    debug_print("Successful authentication on port ", port);
  }
  else if (e != "")
  {
    replace_kb_item( name: "www/"+port+"/"+SCRIPT_NAME+"/auth_KO", 
    		     value: ++ HttpLogin_reauthentication_KO);
    debug_print("Web authentication failed on port ", port, ": ", e);
  }
  replace_kb_item(name: "www/"+port+"/login_time", value: unixtime());

  http_login_release_lock(port);
}

