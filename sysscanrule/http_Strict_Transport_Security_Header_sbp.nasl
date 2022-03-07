include("compat.inc");
include("global_settings.inc");

if(description)
{
 script_id(51799001);
 script_version ("$Revision: 0.1 $");
 script_cvs_date("$Date: 2014/01/29 13:37:00 $");

 script_name(english: "HTTP Strict-Transport-Security: Response Header Usage");

 script_set_attribute(attribute:"synopsis", value:
"The remote web-application takes no steps to mitigate a class of web
application vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote web-application sets no Strict-Transport-Security response header.

HTTP Strict-Transport-Security (HSTS) enforces secure (HTTP over SSL/TLS) connections to the server.
This reduces impact of bugs in web applications leaking session data through cookies and external
links and defends against Man-in-the-middle attacks. HSTS also disables the ability for user's to ignore
SSL negotiation warnings." );
  script_set_attribute(attribute:"solution", value:
"The following header needs to be set on all the pages of the web-application:

Strict-Transport-Security: max-age=16070400;
Be aware that you need a web-server running on port 443 when you set this header. If you don't have it and apply this fix your website will not be available anymore ^^");
  script_set_attribute(attribute:"risk_factor", value: "Low" );

 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Strict-Transport-Security");
 script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc6797");
 script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_summary(english: "Reports web-application that don't use Strict-Transport-Security: header");
 script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) SBP");
 script_family(english: "CGI abuses");

  script_dependencies("http_version.nasl", "ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");
  script_require_ports("Services/www", 443);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");

port = get_http_port(default:443);
host = get_host_name();

# Make sure port is using SSL
transport_ssl_list = get_kb_list("SSL/Transport/"+port);
if (!transport_ssl_list) audit(AUDIT_NOT_LISTEN, "An SSL-enabled HTTP server", port);

soc = http_open_socket(port);
if (! soc) exit(0);

req = http_get(port:port,item:"/");
#send(socket:soc, data: req);
#r = http_recv(socket: soc);

#http_close_socket(soc);
r = https_req_get(port:port , request:req);

if(eregmatch(pattern:'Strict-Transport-Security: (.*)', string:r))
 exit(0,"Correct Strict-Transport-Security found!\n\n");
 else
 resNessus = "Strict-Transport-Security NOT found

"+r;

 security_report_v4(port:port, severity:SECURITY_NOTE, extra:resNessus);
 exit(0,"Incorrect Strict-Transport-Security\r\n");
