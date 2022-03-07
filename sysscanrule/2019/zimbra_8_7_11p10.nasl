#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127133);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/13 10:54:56");

  script_cve_id("CVE-2019-9670");
  script_xref(name:"EDB-ID", value:"46693");
  script_xref(name:"IAVA", value:"2019-A-0276");

  script_name(english:"Zimbra Collaboration Server 8.7.x < 8.7.11p10 XML External Entity injection (XXE) vulnerability");
  script_summary(english:"Checks version of Zimbra Collaboration Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by an XXE vulnerability.");
  script_set_attribute(attribute:"description", value:
"Mailboxd component in Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10
has an XML External Entity injection (XXE) vulnerability.

Note that GizaNE does not identify patch level or components versions for the Synacor Zimbra Collaboration Suite.
You will need to verify if the patch has been applied by executing the command 'zmcontrol -v' from
the command line as the 'zimbra' user.");
  # https://wiki.zimbra.com/wiki/Zimbra_Releases/8.7.11/P10
  script_set_attribute(attribute:"see_also", value:"");
  # https://bugzilla.zimbra.com/show_bug.cgi?id=109129
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/46693");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.7.11p10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9670");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Zimbra Collaboration Autodiscover Servlet XXE and ProxyServlet SSRF');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("zimbra_web_detect.nbin");
  script_require_keys("www/zimbra_zcs", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 7071);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('webapp_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);
port = get_http_port(default:443);

install = get_install_from_kb(
  appname      : 'zimbra_zcs',
  port         : port,
  exit_on_fail : TRUE
);

app = 'Zimbra Collaboration Server';
dir = install['dir'];
version = install['ver'];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);

# Versions 8.7.x <= 8.7.11.x, detected version is in the following format: 8.7.11_GA_xxxx
if (version !~ '8\\.7\\.([0-9]|10|11)') audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 8.7.11 Patch 10\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
