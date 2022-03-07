##
# 
##

include('compat.inc');

if (description)
{
  script_id(147870);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2021-21481");
  script_xref(name:"IAVA", value:"2021-A-0138");

  script_name(english:"SAP NetWeaver AS JAVA Missing Authorization Check (3022422)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be missing an authorization check");
  script_set_attribute(attribute:"description", value:
"The MigrationService, which is part of SAP NetWeaver versions 7.10, 7.11, 7.20, 7.30, 7.31, 7.40, 7.50, does not
perform an authorization check. This might allow an unauthorized attacker to access configuration objects, including
such that grant administrative privileges. This could result in complete compromise of system confidentiality,
integrity, and availability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=571343107");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3022422");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/18");

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

app = 'SAP Netweaver Application Server (AS)';

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  {'min_version' : '7.10', 'max_version' : '7.11', 'fixed_display' : 'See vendor advisory' },
  {'min_version' : '7.20', 'max_version' : '7.20', 'fixed_display' : 'See vendor advisory' },
  {'min_version' : '7.30', 'max_version' : '7.30', 'fixed_display' : 'See vendor advisory' },
  {'min_version' : '7.31', 'max_version' : '7.31', 'fixed_display' : 'See vendor advisory' },
  {'min_version' : '7.40', 'max_version' : '7.40', 'fixed_display' : 'See vendor advisory' },
  {'min_version' : '7.50', 'max_version' : '7.50', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
