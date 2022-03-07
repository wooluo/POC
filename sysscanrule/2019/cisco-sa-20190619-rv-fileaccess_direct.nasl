#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126004);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/19 12:44:33");

  script_cve_id("CVE-2019-1898");
  script_xref(name:"TRA", value:"TRA-2019-29");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo65034");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo65037");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo65038");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190619-rv-fileaccess");

  script_name(english:"Cisco RV110W, RV130W, and RV215W Routers Syslog Disclosure (cisco-sa-20190619-rv-fileaccess)");
  script_summary(english:"Checks for an information disclosure vulnerability.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of the Cisco
Small Business Wireless-N VPN Router installed on the remote host is
affected by an information disclosure vulnerability. An
unauthenticated, remote attacker can exploit this to disclose 
potentially sensitive information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://www.WebRAY.com/security/research/tra-2019-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20190619-rv-fileaccess.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1898");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv110w_wireless-n_vpn_firewall");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv130w_wireless-n_multifunction_vpn_router");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv215w_wireless-n_vpn_router");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443, 8000, 8007, 8081, 8443);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');

app = 'Cisco Small Business RV110W, RV130W, RV215W Series Router';

port = get_http_port(default:443);

# sanity check this is likely to be RV320/RV325
res = http_get_cache(item:'/', port:port, exit_on_fail:TRUE);

if ('router.copyright' >!< res &&
    'router.aboutcopyright' >!< res &&
    'cisco_logo_about.png' >!< res)
{
  audit(AUDIT_WEB_FILES_NOT, app, port);
}

item = '/_syslog.txt';
res = http_send_recv3(method:'GET', item:item, port:port);

# Examples from syslog.txt on targets
# 2019-03-01 19:21:40 RV110W user.debug syslog: igmp-proxy *** WLAN:8 SIOWLANSNPADDGRP xxyyzz <-> xx:yy:zz
# 2010-02-26 11:25:56 RV215W syslog.err syslog-ng[366]: Connection broken to AF_INET((NULL):514), reopening in 60 seconds
if (isnull(res) || res[2] !~ "\d{2,4}-\d{2,4}-\d{2,4}\s+\d{1,2}:\d{1,2}:\d{1,2}\s+RV\d{3}W")
  audit(AUDIT_LISTEN_NOT_VULN, app, port);

security_report_v4(severity:SECURITY_WARNING, port:port, generic:TRUE, request:[http_last_sent_request()]);
