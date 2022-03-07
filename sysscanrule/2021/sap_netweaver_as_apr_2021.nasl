##
# 
##

include('compat.inc');

if (description)
{
  script_id(148573);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/22");

  script_cve_id(
    "CVE-2021-21485",
    "CVE-2021-21492",
    "CVE-2021-27598",
    "CVE-2021-27601",
    "CVE-2021-27603"
  );
  script_xref(name:"IAVA", value:"2021-A-0165");

  script_name(english:"SAP NetWeaver AS Java and AS ABAP Multiple Vulnerabilities (Apr 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SAP Netweaver Application Server for Java installed on the remote host may be affected by multiple
vulnerabilities, including the following:

  - An unauthorized attacker may be able to entice an administrator to invoke telnet commands of an SAP
    NetWeaver Application Server for Java that allow the attacker to gain NTLM hashes of a privileged user.
    (CVE-2021-21485)

  - SAP NetWeaver AS JAVA (Customer Usage Provisioning Servlet), versions - 7.31, 7.40, 7.50, allows an
    attacker to read some statistical data like product version, traffic, timestamp etc. because of missing
    authorization check in the servlet. (CVE-2021-27598)

  - SAP NetWeaver AS Java (Applications based on HTMLB for Java) allows a basic-level authorized attacker to
    store a malicious file on the server. When a victim tries to open this file, it results in a cross-site
    scripting (XSS) vulnerability and the attacker can read and modify data. However, the attacker does not
    have control over kind or degree. (CVE-2021-27601)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=573801649");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3027937");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3025637");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/2963592");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3001824");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3028729");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27598");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = 'SAP Netweaver Application Server (AS)';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

# We want to use the extra_version here, not the version
# Use get_single_install() to avoid exiting if there's an unknown version as is the case for ABAP (only has extra_version)
# and to get the ABAP Version app_info extra that is unavailable if passing kb_ver to get_app_info()
var app_info = get_single_install(app_name:app, exit_if_unknown_ver:FALSE, port:port);
app_info['version'] = get_kb_item_or_exit('www/netweaver/' + port + '/extra_version');

# vcf::parse_version() won't parse versions like 740 correctly, so add a fake  .0 to the end of it and set a
# display_version
if ("." >!< app_info['version'])
{
  app_info['display_version'] = app_info['version'];
  app_info['version'] = app_info['version'] + '.0';
}
app_info['parsed_version'] = vcf::parse_version(app_info['version']);
app_info['webapp'] = TRUE;
app_info['port'] = port;

var fix = 'See vendor advisory';
var flags = make_array();
var constraints;

if (app_info['ABAP Version'])
{
  constraints = [
    {'equal' : '731', 'fixed_display' : fix },
    {'equal' : '740', 'fixed_display' : fix },
    {'equal' : '750', 'fixed_display' : fix }
  ];
}
else
{
  constraints = [
    {'min_version' : '7.10', 'max_version' : '7.11', 'fixed_display' : 'See vendor advisory' },
    {'equal' : '7.20', 'fixed_display' : 'See vendor advisory' },
    {'equal' : '7.30', 'fixed_display' : 'See vendor advisory' },
    {'equal' : '7.31', 'fixed_display' : 'See vendor advisory' },
    {'equal' : '7.40', 'fixed_display' : 'See vendor advisory' },
    {'equal' : '7.50', 'fixed_display' : 'See vendor advisory' }
  ];
  flags = make_array('xss', TRUE);
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
