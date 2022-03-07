#
# 
#

include('compat.inc');

if (description)
{
  script_id(136808);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/27");

  script_cve_id("CVE-2020-8617");
  script_xref(name:"IAVA", value:"2020-A-0217");

  script_name(english:"ISC BIND Denial of Service");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by an assertion failure vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in ISC BIND versions 9.11.18 / 9.11.18-S1 / 9.12.4-P2 / 9.13 / 9.14.11
/ 9.15 / 9.16.2 / 9.17 / 9.17.1 and earlier. An unauthenticated, remote attacker can exploit this issue, via a
specially-crafted message, to cause the service to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2020-8617");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the patched release most closely related to your current version of BIND.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();

app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

constraints = [
  { 'min_version' : '9.0.0', 'max_version' : '9.11.18', 'fixed_display' : '9.11.19' },
  { 'min_version' : '9.9.3-S1', 'max_version' : '9.11.18-S1', 'fixed_display' : '9.11.19-S1' },
  { 'min_version' : '9.14.0', 'max_version' : '9.14.11', 'fixed_display' : '9.14.12' },
  { 'min_version' : '9.16.0', 'max_version' : '9.16.2', 'fixed_display' : '9.16.3'},
  # The below have no fixed versions
  { 'min_version' : '9.12.0', 'max_version' : '9.12.4-P2', 'fixed_display' : 'Update to the latest available stable release' },
  { 'min_version' : '9.17.0', 'max_version' : '9.17.1', 'fixed_display' : 'Update to the latest available stable release' },
  { "min_version" : "9.13.0", "max_version" : "9.13.3" , 'fixed_display' : 'Update to the latest available stable release' },
  { "min_version" : "9.15.0", "max_version" : "9.15.7", 'fixed_display' : 'Update to the latest available stable release' }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
