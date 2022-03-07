#
# 
#

include("compat.inc");

if (description)
{
  script_id(39446);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVT", value:"0001-T-0535");

  script_name(english:"Apache Tomcat Detection");
  script_summary(english:"Attempts to detect Apache Tomcat servers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is an Apache Tomcat server.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect a remote Apache Tomcat
web server.");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");
include("install_func.inc");

# a script global that indicates if we identified the server as tomcat
found_tomcat = FALSE;

# a script global that stores the source of the version string
version_source = NULL;

# a script global containing the version
version = NULL;

##
# Safechecks version to ensure it has a number at least
#
# @param ver the ver to check
# @return ver if the ver param contains at least a number,
#         UNKNOWN_VER otherwise.
##
function safecheck_ver(ver)
{
  if (ver =~ "\d+")
    return ver;
  else
    return UNKNOWN_VER;
}

##
# Extracts the version number from the index or error page. There are other
# places that we might able to check (for example RELEASE-NOTES.txt) but
# if the error page has been modified its unlikely /docs will be installed.
#
# @param port the port to scan
# @return FALSE on failure to extract the version. TRUE on success.
# @sideaffect found_tomcat, version_source, and version might get modified
##
function find_version(port)
{
  # before we send a request, it isn't that crazy for the default page to be
  # present. So let's just dip into the cache and see what we have
  var res = http_get_cache(port:port, item:'/');

  # <title>Apache Tomcat</title>
  # <title>Tomcat v3.2 (final)</title>
  # <title>Apache Tomcat/5.0.27</title>
  # <title>Apache Tomcat/7.0.52</title>
  # <title>Apache Tomcat (TomEE)/7.0.55 (1.7.1)</title>
  # <title>Apache Tomcat/8.5.23</title>
  # <title>Apache Tomcat/9.0.0.M20</title>
  var matches = pregmatch(pattern:"<title>(?:Apache )?Tomcat(?:(?:[/ ]([a-zA-Z\.0-9-]+))|(?: \(TomEE\)/([a-zA-Z\.0-9]+))|</title>)", string:res);
  if (!empty_or_null(matches))
  {
    found_tomcat = TRUE;
    if (!empty_or_null(matches[1]))
    {
      version = safecheck_ver(ver:matches[1]);
      version_source = matches[0];
      return TRUE;
    }
    else if (!empty_or_null(matches[2]))
    {
      version = safecheck_ver(ver:matches[2]);
      version_source = matches[0];
      return TRUE;
    }
  }

  # the most likely place to uncover the version is the error page. Although
  # this can be replaced with a custom error page or the version string can
  # simply be modified
  var url = "/nessus-check/" + SCRIPT_NAME;
  res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE);
  if (empty_or_null(res) || "404" >!< res[0] || empty_or_null(res[2]))
  {
    http_disable_keep_alive();
    res = http_send_recv3(method:"GET", item:url, host:get_host_ip(), port:port, fetch404:TRUE);
  }

  if (!empty_or_null(res) && "404" >< res[0] && !empty_or_null(res[2]))
  {
    # Note that all version support the <h3> syntax in the footer. However,
    # historically we've used the <title> logic so I'll attempt to perserve
    # that. Versions 8.5+ no longer user this <title> format though.
    #
    # <title>Apache Tomcat/5.0.27 - Error report</title>
    # <title>Apache Tomcat/6.0.39 - Error report</title>
    # <title>Apache Tomcat/7.0.52 - Error report</title>
    # <title>Apache Tomcat (TomEE)/7.0.63 (1.7.3) - Error report</title>
    # <title>Apache Tomcat/8.0.32 (Ubuntu) - Error report</title>
    # <h3>Apache Tomcat/8.5.23</h3>
    # <h3>Apache Tomcat/9.0.0.M20</h3>
    matches = pregmatch(pattern:"<(?:title|h3)>Apache Tomcat(?:(?:/([a-zA-Z\.0-9-]+))|(?: \(TomEE\)/([a-zA-Z\.0-9]+)))", string:res[2]);
    if (!empty_or_null(matches))
    {
      found_tomcat = TRUE;
      if (!empty_or_null(matches[1]))
      {
        version = safecheck_ver(ver:matches[1]);
        version_source = matches[0];
        return TRUE;
      }
      else if (!empty_or_null(matches[2]))
      {
        version = safecheck_ver(ver:matches[2]);
        version_source = matches[0];
        return TRUE;
      }
    }
  }

  return FALSE;
}

##
# This function takes our version source and passes it to backport.inc to determine
# if the remote server might contain backported patches.
#
# @return NULL
# @sideaffect version_source, and version might get modified
## 
function handle_backport(port)
{
  if (empty_or_null(version) || empty_or_null(version_source))
  {
    return NULL;
  }

  # Better format output
  if ("<title>" >< version_source)
    version_source = str_replace(string:version_source, find:'<title>', replace:'');
  if ("<h3>" >< version_source)
    version_source = str_replace(string:version_source, find:'<h3>', replace:'');

  # store the original values. These do get used downstream
  set_kb_item(name:"tomcat/" + port + "/orig_error_version", value:version);
  set_kb_item(name:"tomcat/" + port + "/orig_version_source", value:version_source);

  # Look into backports to see if our version banner might represent a banner that
  # has seen backports
  var backported_source = get_backport_banner(banner:version_source);
  if (backported == FALSE)
  {
    # Identify ManageEngine products.
    var res = http_send_recv3(method:"GET", item:"/event/index2.do", port:port, follow_redirect:1);
    if (!empty_or_null(res) && !empty_or_null(res[2]) &&
        ("<title>ManageEngine" >< res[2] && ">ZOHO Corp.</a>" >< res[2] && 'support@manageengine.com">' >< res[2]))
    {
      backported = TRUE;
    }
  }

  # Use new variables so that 'version' and 'version_source' remain the "actual" version
  local_var bp_version = version;
  local_var bp_version_source = version_source;
  if (backported_source != version_source)
  {
    # we have to reparse the backported banner
    var matches = pregmatch(pattern:".*Apache Tomcat/([0-9a-zA-Z\\.]+).*", string:backported_source);
    if (empty_or_null(matches))
    {
      exit(1, "Failed to extract the version from the backported banner from port " + port + ".");
    }
    bp_version_source = matches[0];
    bp_version = matches[1];
  }

  # Better format output
  if ("<title>" >< bp_version_source)
    bp_version_source = str_replace(string:bp_version_source, find:'<title>', replace:'');
  if ("<h3>" >< bp_version_source)
    bp_version_source = str_replace(string:bp_version_source, find:'<h3>', replace:'');

  set_kb_item(name:"tomcat/" + port + "/error_version", value:bp_version);
  set_kb_item(name:"tomcat/" + port + "/version_source", value:bp_version_source);
  set_kb_item(name:"tomcat/"+port+"/backported", value:backported);
}

port = get_http_port(default:8080);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

# Old school Tomcat. You can just pull the version out of this banner:
#
# Servlet-Engine: Tomcat Web Server/3.2.4 (JSP 1.1; Servlet 2.2; Java 1.6.0_45; Windows 2003 5.2 x86; java.vendor=Sun Microsystems Inc.)
# Servlet-Engine: Tomcat Web Server/3.1 (JSP 1.1; Servlet 2.2; Java 1.4.2_10; Windows XP 5.1 x86; java.vendor=Sun Microsystems Inc.)
# Servlet-Engine: Tomcat Web Server/3.2 (final) (JSP 1.1; Servlet 2.2; Java 1.3.0_02; Windows NT (unknown) 6.2 x86; java.vendor=Sun Microsystems Inc.)
matches = pregmatch(pattern:"Servlet-Engine: Tomcat Web Server/([^ ]+)", string:banner);
if (!empty_or_null(matches))
{
  found_tomcat = TRUE;
  version_source = matches[0];
  version = safecheck_ver(ver:matches[1]);
}
# From 4.0-8.0 the server used various Server fields we can rely on
#
# Server: Apache TomEE
# Server: Apache-Coyote/1.1
# Server: Apache Coyote/1.0
# Server: Apache Tomcat/4.0.6 (HTTP/1.1 Connector)
else if (preg(pattern:"^Server: Apache[ -](TomEE|Coyote|Tomcat)", string:banner, multiline:TRUE) ||
# We can also identify Tomcat (or services built on Tomcat) using the X-Powered-By field.
# This is turned off by default in mainline Tomcat, but you can find these in the wild.
# Unfortunately, the version in the X-Powered-By (at least for JBoss) doesn't appear to
# be reliable.
#
# X-Powered-By: Servlet 2.4; JBoss-4.0.5.GA/Tomcat-5.5
# X-Powered-By: Servlet/3.1 JSP/2.3 (Apache Tomcat/8.0.36 Java/Oracle Corporation/1.8.0_151-b12)
# X-Powered-By: Servlet 2.4; Tomcat-5.0.28/JBoss-3.2.7 (build: CVSTag=JBoss_3_2_7 date=200501280217)
  preg(pattern:"^X-Powered-By:[^\r\n]*Tomcat[-/]", string:banner, multiline:TRUE))
{
  found_tomcat = TRUE;
  find_version(port:port);
}
# Tomcat 8.5+ doesn't contain a Server field. Also Tomcat behind nginx is
# apparently a popular thing. Also look for mod_jk... we should probably just
# allow all Apache but that is so many servers. However, if this is a paranoid
# scan then try all the servers!
#
# mod_jk examples:
# Server: Apache/2.4.7 (Ubuntu) mod_jk/1.2.37 OpenSSL/1.0.1f
# Server: Apache/2.2.27 (Win32) mod_ssl/2.2.27 OpenSSL/1.0.1h mod_jk/1.2.36
# Server: Apache/2.2.25 (Win32) mod_jk/1.2.31
else if (report_paranoia >= 2 || "Server:" >!< banner ||
         "Server: nginx/" >< banner || "mod_jk/" >< banner)
{
  find_version(port:port);
}

if (found_tomcat == FALSE)
{
  audit(AUDIT_WRONG_WEB_SERVER, port, "Apache Tomcat");
}

set_kb_item(name:"www/tomcat", value:TRUE);
set_kb_item(name:"www/"+port+"/tomcat", value:TRUE);

extra_array = NULL;
if (!empty_or_null(version))
{
  handle_backport(port:port);
  extra_array = make_array("backported", backported, "source", version_source);
}


if("M" >< version){
    version = str_replace(string:version, find:'-', replace:'.');
}

register_install(
  app_name:"Apache Tomcat",
  path:'/',
  version:version,
  port:port,
  extra:extra_array,
  webapp:TRUE,
  cpe: "cpe:/a:apache:tomcat");

report_installs(app_name:"Apache Tomcat", port:port);
