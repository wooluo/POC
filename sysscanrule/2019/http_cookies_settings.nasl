#TRUSTED 95706e7233702db45e033f859a23e715330fac46a07ee02f01417afea0b984a7bc24ba1452d80b342cca8178c49cb6e683eea978e57ed78a78ca340271e6d5a77d0aacdd8c4e96db0ca94da2287e992b633f7756b98173f85cd15ce8da385e653123f45ed26c349b00ad4b1bd49c5a26956ec6fc34453363da12779fffbb58d8a3a132d41426944996bf088c57d6433165017b2d28808b8bf38e5f6b36bcee2d8476695fe63555417bb03d129f09f91b288ab3907c47dca7e908fc8bdf4e4da8f0c73e3cee05fea124624920abbc762dedbef4d8b56674715b9945e2c601b18d6fdb58d9733b5f428ee00f5379a51fceef14c0cb391f08a67949ecd1eae66258f8248f5b117bdcbe007bb5a1241702bc5913982103ae10c4646c4c01012cee1f46f89875c7c0438b6782ec23d56073384e0c3cca2ab04b3a79970b3adbfdb9a9e45788060b8c26e87b3d0fe7142d8c302f75ba7a0cece316fd5bba19cc2e40377125a166463f0bc0bf51628f1e8932c59b1f06dfcb0d749ca66b251ddff07986d8730bd0de30e3c50e8215c841e62e91489f3024770009e5b3ac722fb2ff54fb477cf4c3921143bc02445602eabf773d266c6ccc40722d51eaf0df20fbbc9daedbc2dfc23598a3a284eebda2d6dab514ea57edf5110691d27a307959167c0903ec02762a911565e997621d89a36e03d6e02060f59c06d916360f7ea912a8e9ef
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42893);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2019/06/17");

 script_name(english:"HTTP cookies import");
 script_summary(english:"Import HTTP cookies in Netscape format");

 script_set_attribute(attribute:"synopsis", value: "HTTP cookies import.");
 script_set_attribute(attribute:"description", value:
"This plugin imports cookies for all web tests.

The cookie file must be in 'Netscape format'.

It does not perform any test by itself.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_copyright(english:"This script is Copyright (C) 2009-2019 WebRAY Network Security, Inc.");
 script_family(english:"Settings");

 script_add_preference(name: "Cookies file : ", type: "file", value:"");
 script_dependencie("ping_host.nasl", "global_settings.nasl");
 exit(0);
}

global_var	debug_level;

include("misc_func.inc");

global_var	same_hosts_l;
same_hosts_l = make_array();

function _wm_same_host(h)
{
 local_var	n, i;
 n = tolower(get_host_name());
 if (n == h) return 1;
 i = get_host_ip();
 if (i == h) return 1;

 # Do not call same_host, it was broken
 return 0;
}

function wm_same_host(h)
{
 h = tolower(h);
 if (same_hosts_l[h] == 'y') return 1;
 if (same_hosts_l[h] == 'n') return 0;
 if (_wm_same_host(h: h))
 {
  same_hosts_l[h] = 'y';
  return 1;
 }
 else
 {
  same_hosts_l[h] = 'n';
  return 0;
 }
}

#### Functions from http_cookie_jar.inc, to avoid signing it

global_var	CookieJar_value, CookieJar_version, CookieJar_expires,
		CookieJar_comment, CookieJar_secure, CookieJar_httponly,
		CookieJar_domain, CookieJar_port,
		CookieJar_is_disabled, CookieJar_autosave;

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
    key = strcat(name, '=', path);
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

function store_cookiejar()
{
  local_var	k;
  if (isnull(CookieJar_value)) return;
  foreach k (keys(CookieJar_value))
     store_1_cookie(key: k, jar: _FCT_ANON_ARGS[0]);
}

#### end of cookie functions

opt = get_kb_item("global_settings/debug_level");
debug_level = int(opt);
if (debug_level < 0) debug_level = 0;

# Import Netscape cookies

if (script_get_preference("Cookies file : ")) # Avoid dirty warning
  content = script_get_preference_file_content("Cookies file : ");
else
  exit(0, "No cookie file.");

n = 0;
if (strlen(content) > 0)
{
  CookieJar_autosave = NULL;

  lines = split(content, keep: 0);
  content = NULL;	# Free memory
  now = unixtime();

  foreach l (lines)
  {
    if (l =~ '^[ \t]*#') continue; # ignore comments
    if (l =~ '^[ \t]*$') continue; # ignore all whitespace lines
# Fields:
# 0 domain
# 1 flag - indicates if all machines within a given domain can access the variable.
# 2 path
# 3 secure
# 4 expiration - UNIX time
# 5 name
# 6 value
    v = split(l, sep: '\t', keep: 0);
    m = max_index(v);

    if (m < 6 || m > 8)
      exit(1, 'Invalid cookies file (unexpected line).');

    if (v[3] == "TRUE") sec = 1; else sec = 0;
    t = int(v[4]);	# Expiration date

    # nb: Firebug has 8 fields per line, with a field for max-age between 
    #     expiration and cookie name.
    if (m == 8)
    {
      name = v[6];
      val =  v[7];
    }
    else
    {
      name = v[5];
      val =  v[6];
    }

    # Import session cookies, but reject expired cookies
    if (t == 0 || now < t)
    {
      set_http_cookie(path: v[2], domain: v[0], secure: sec, name:name, value:val);
      n ++;
    }
    else
      debug_print(level: 3, "Expired cookie: t=", t, " Path=", v[2], " Domain=", v[0], " Secure=", sec, " Name=", name, " Value=", val);
  }

  if (n == 0)
    exit(1, 'No cookies were found in the given file.');

  debug_print(n, ' cookies imported.\n');
  # It is not always related to authentication, but this will be the main use
  store_cookiejar("FormAuth");
  store_cookiejar();
  lines = NULL;	# Free memory
}
else
  exit(0, "Cookie file is empty.");

