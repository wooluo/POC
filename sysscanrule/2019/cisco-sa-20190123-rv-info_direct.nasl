#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121395);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/05 14:22:52");

  script_cve_id("CVE-2019-1653");
  script_bugtraq_id(106732);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-rv-info");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg85922");

  script_name(english:"Cisco Small Business RV320 and RV325 Routers Information Disclosure Vulnerability (cisco-sa-20190123-rv-info) (remote check)");
  script_summary(english:"Attempts to obtain the router configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Small Business router is affected by a remote
information disclosure vulnerability. A remote, unauthenticated
attacker can exploit this, via a simple HTTP GET or POST request, to
obtain the configuration of the router. This configuration includes
device credentials in the form of a plaintext username and an MD5
hashed password that is trivial to crack.

These credentials could then be used to authenticate to the router
and can be leveraged with a command injection vulnerability
(CVE-2019-1652) to allow an attacker to execute arbitrary commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-info
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.redteam-pentesting.de/en/advisories/rt-sa-2018-002/-cisco-rv320-unauthenticated-configuration-export
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2019/Mar/59");
  script_set_attribute(attribute:"see_also", value:"https://github.com/0x27/CiscoRV320Dump");
  script_set_attribute(attribute:"solution", value:
"Refer to Cisco bug ID CSCvg85922 for any available patches, or
contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1653");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco RV320 and RV325 Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320_dual_gigabit_wan_vpn_router");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320_dual_gigabit_wan_wf_vpn_router");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325_dual_gigabit_wan_vpn_router");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325_dual_gigabit_wan_wf_vpn_router");
  script_set_attribute(attribute:"exploited_by_GizaNE", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443, 8000, 8007, 8081, 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");
include("data_protection.inc");

app = "Cisco Small Business RV320 Series Router";

port = get_http_port(default:443);

# sanity check this is likely to be RV320/RV325
res = http_get_cache(item:'/', port:port, exit_on_fail:TRUE);

if ('<form name="form_contents" method="post" action="/cgi-bin/userLogin.cgi">' >!< res ||
    '<input type="hidden" name="portalname" value="CommonPortal">' >!< res ||
    '<input type="hidden" name="auth_key"' >!< res)
{
  audit(AUDIT_WEB_FILES_NOT, app, port);
}

item = '/cgi-bin/config.exp';
res = http_send_recv3(method:'GET', item:item, port:port);

if (isnull(res) ||
    '####sysconfig####' >!< res[2] ||
    'MODEL=' >!< res[2] ||
    'PASSWD=' >!< res[2])
{
  res = http_send_recv3(method:'POST', item:item, data:'submitbkconfig=0', port:port);
  if (isnull(res) ||
      '####sysconfig####' >!< res[2] ||
      'MODEL=' >!< res[2] ||
      'PASSWD=' >!< res[2])
  {
    audit(AUDIT_LISTEN_NOT_VULN, app, port);
  }
  else
    method = 'POST';
}
else
  method = 'GET';

output = data_protection::sanitize_user_full_redaction(output:res[2]);

trailer = 'Which returns the following page via a ' + method  + ' request:\n\n' + output;
report = get_vuln_report(items:item, port:port, trailer:trailer);
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
