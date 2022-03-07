##
# 
##

include('compat.inc');

if (description)
{
  script_id(145705);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id(
    "CVE-2020-6224",
    "CVE-2020-26816",
    "CVE-2020-26820",
    "CVE-2021-21446"
  );
  script_xref(name:"IAVA", value:"2021-A-0043");

  script_name(english:"SAP NetWeaver AS Java and AS ABAP Multiple Vulnerabilities (Jan 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SAP NetWeaver AS Java or ABAP detected on the remote host is affected by multiple vulnerabilities, as
follows:

  - SAP NetWeaver AS Java (HTTP Service), versions 7.10, 7.11, 7.20, 7.30, 7.31, 7.40, 7.50, allows an
    attacker with administrator privileges to access user sensitive data such as passwords in trace files,
    when the user logs in and sends request with login credentials, leading to Information Disclosure.
    (CVE-2020-6224)

  - SAP NetWeaver AS JAVA, versions - 7.20, 7.30, 7.31, 7.40, 7.50, allows an attacker who is authenticated as
    an administrator to use the administrator console, to expose unauthenticated access to the file system and
    upload a malicious file. The attacker or another user can then use a separate mechanism to execute OS
    commands through the uploaded file leading to Privilege Escalation and completely compromise the
    confidentiality, integrity and availability of the server operating system and any application running on
    it. (CVE-2020-26820)

  - SAP AS JAVA (Key Storage Service), versions - 7.10, 7.11, 7.20 ,7.30, 7.31, 7.40, 7.50, has the key
    material which stored in the SAP NetWeaver AS Java Key Storage service stored in the database in the DER
    encoded format and is  encrypted. This enables an attacker who has administrator access to the SAP
    NetWeaver AS Java to decode the keys of missing encryption and get some application data and client
    credentials of adjacent systems. This highly Confidentiality as information disclosed could contain client
    credentials of adjacent systems. CVE-2020-26816)

  - SAP NetWeaver AS ABAP, versions 740, 750, 751, 752, 753, 754, 755, allows an unauthenticated attacker to
    prevent legitimate users from accessing a service, either by crashing or flooding the service, this has a
    high impact on the availability of the service. (CVE-2021-21446)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=564760476");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'equal' : '754', 'fixed_display' : fix },
    {'equal' : '755', 'fixed_display' : fix }
  ];
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
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
