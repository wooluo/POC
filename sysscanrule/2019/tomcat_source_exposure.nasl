#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# v. 1.00 (last update 24.09.02)
#
#
# Changes by WebRAY: 
# - removed un-necessary requests
# - revised plugin title (4/7/2009)

include("compat.inc");

if (description)
{
 script_id(11176);
 script_version("1.31");
 script_cvs_date("Date: 2019/06/17 10:56:28");

 script_cve_id("CVE-2002-1148", "CVE-2002-1394");
 script_bugtraq_id(5786, 6562);

 script_name(english:"Apache Tomcat Catalina org.apache.catalina.servlets.DefaultServlet Source Code Disclosure");
 script_summary(english:"Tomcat 4.x JSP source exposure.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(
   attribute:"description",
   value:
"The version of Apache Tomcat running on the remote host is affected by
an information disclosure vulnerability. It is possible to view source
code using the default servlet :

  org.apache.catalina.servlets.DefaultServlet

A remote attacker can exploit this information to mount further
attacks.

This version of Tomcat reportedly affected by additional
vulnerabilities; however, GizaNE has not checked for them."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/28");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2019 Felix Huber");
 script_family(english:"CGI abuses");
 
 script_dependencies("tomcat_error_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("installed_sw/Apache Tomcat");
 
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

function check(sfx, port)
{
   local_var url, req, r;

   url = string("/servlet/org.apache.catalina.servlets.DefaultServlet", sfx);
   req = http_get(item:url, port:port);
   r = http_keepalive_send_recv(port:port, data:req);
   if( r == NULL ) exit(0);

   if("<%@" >< r){
       security_warning(port);
       exit(0);
      }
      
    if(" 200 OK" >< r)
    {
     if("Server: Apache Tomcat/4." >< r)
     {
                security_warning(port); 
                exit(0); 
      } 
    }
}

port = get_http_port(default:8080);


if(!get_port_state(port))exit(0);


files = get_kb_list(string("www/",port, "/content/extensions/jsp"));
if(!isnull(files))
 {
  files = make_list(files);
  file = files[0];
 }
else file = "/index.jsp";

check(sfx:file, port:port);
