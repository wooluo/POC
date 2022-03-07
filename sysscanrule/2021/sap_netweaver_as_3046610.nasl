##
# 
##


include('compat.inc');

if (description)
{
  script_id(149848);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id("CVE-2021-27611");
  script_xref(name:"IAVA", value:"2021-A-0245");

  script_name(english:"SAP NetWeaver AS ABAP Command Injection (May 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver server is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in SAP NetWeaver Application Server ABAP due to a flaw in the RDDPUTJR program. 
An authenticated, local attacker can exploit this, by executing an ABAP report when the attacker has access to the 
local SAP system, to execute arbitrary command or create a denial of service condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3046610");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=576094655");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27611");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var port, app, app_info, fix, constraints;

app = 'SAP Netweaver Application Server (AS)';

port = get_http_port(default:443);

# We want to use the extra_version here, not the version
# Use get_single_install() to avoid exiting if there's an unknown version as is the case for ABAP (only has extra_version)
# and to get the ABAP Version app_info extra that is unavailable if passing kb_ver to get_app_info()
app_info = get_single_install(app_name:app, exit_if_unknown_ver:FALSE, port:port);
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

fix = 'See vendor advisory';

if (app_info['ABAP Version'])
{
  constraints = [
    {'equal' : '700', 'fixed_display' : fix },
    {'equal' : '701', 'fixed_display' : fix },
    {'equal' : '702', 'fixed_display' : fix },
    {'equal' : '730', 'fixed_display' : fix },
    {'equal' : '731', 'fixed_display' : fix }
  ];
}
else
{
    audit(AUDIT_INST_VER_NOT_VULN, app);
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
