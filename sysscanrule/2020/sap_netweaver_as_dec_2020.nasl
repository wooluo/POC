##
# 
##

include('compat.inc');

if (description)
{
  script_id(144081);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/14");

  script_cve_id(
    "CVE-2020-26816",
    "CVE-2020-26826",
    "CVE-2020-26829",
    "CVE-2020-26835"
  );
  script_xref(name:"IAVA", value:"2020-A-0564");

  script_name(english:"SAP NetWeaver AS Java and AS ABAP Multiple Vulnerabilities (Dec 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SAP NetWeaver AS Java or ABAP detected on the remote host is affected by multiple vulnerabilities, as
follows:

  - SAP NetWeaver AS JAVA (P2P Cluster Communication), versions - 7.11, 7.20, 7.30, 7.31, 7.40, 7.50, allows arbitrary
    connections from processes because of missing authentication check, that are outside the cluster and even outside
    the network segment dedicated for the internal cluster communication. As result, an unauthenticated attacker can
    invoke certain functions that would otherwise be restricted to system administrators only, including access to
    system administration functions or shutting down the system completely. (CVE-2020-26829)

  - Process Integration Monitoring of SAP NetWeaver AS JAVA, versions - 7.31, 7.40, 7.50, allows an attacker to upload
    any file (including script files) without proper file format validation, leading to Unrestricted File Upload.
    (CVE-2020-26826)

  - SAP AS JAVA (Key Storage Service), versions - 7.10, 7.11, 7.20 ,7.30, 7.31, 7.40, 7.50, has the key material which
    is stored in the SAP NetWeaver AS Java Key Storage service stored in the database in the DER encoded format and is
    not encrypted. This enables an attacker who has administrator access to the SAP NetWeaver AS Java to decode the keys
    because of missing encryption and get some application data and client credentials of adjacent systems. This highly
    impacts Confidentiality as information disclosed could contain client credentials of adjacent systems.
    (CVE-2020-26816)

  - SAP NetWeaver AS ABAP, versions - 740, 750, 751, 752, 753, 754 , does not sufficiently encode URL which allows an
    attacker to input malicious java script in the URL which could be executed in the browser resulting in Reflected
    Cross-Site Scripting (XSS) vulnerability. (CVE-2020-26835)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=564757079");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26829");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

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
    {'equal' : '740', 'fixed_display' : fix },
    {'equal' : '750', 'fixed_display' : fix },
    {'equal' : '751', 'fixed_display' : fix },
    {'equal' : '752', 'fixed_display' : fix },
    {'equal' : '753', 'fixed_display' : fix },
    {'equal' : '754', 'fixed_display' : fix }
  ];

  flags = {'xss':TRUE};
}
else
{
  constraints = [
    {'equal' : '7.10', 'fixed_display' : fix },
    {'equal' : '7.11', 'fixed_display' : fix },
    {'equal' : '7.20', 'fixed_display' : fix },
    {'equal' : '7.30', 'fixed_display' : fix },
    {'equal' : '7.31', 'fixed_display' : fix },
    {'equal' : '7.40', 'fixed_display' : fix },
    {'equal' : '7.50', 'fixed_display' : fix }
  ];

  flags = {};
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, flags:flags, severity:SECURITY_HOLE);
