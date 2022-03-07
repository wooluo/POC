
##
# 
##



include('compat.inc');

if (description)
{
  script_id(152191);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/05");

  script_cve_id("CVE-2021-29736");
  script_xref(name:"IAVA", value:"2021-A-0362");

  script_name(english:"IBM WebSphere Application Server 7.0.x <= 7.0.0.45 / 8.0.x <= 8.0.0.14 / 8.5.x < 8.5.5.21 / 9.0.x < 9.0.5.9 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WebSphere Application Server installed on the remote host is affected by a privilege escalation
vulnerability that allows a remote authenticated user to gain elevated privileges on the system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6476678");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.21, 9.0.5.9, or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PH34690.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['version'], app);

if ('PH34690' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var fix = 'Interim Fix PH34690';
var constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.45', 'fixed_display':fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_display':fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.20', 'fixed_display':'8.5.5.21 or ' + fix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.5.8', 'fixed_display':'9.0.5.9 or ' + fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
