##
# 
##

include('compat.inc');

if (description)
{
  script_id(142711);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/11");

  script_cve_id("CVE-2020-24384");

  script_name(english:"A10 Networks ACOS/aGalaxy GUI RCE (A10-2020-0006)");

  script_set_attribute(attribute:"synopsis", value:
"The remote A10 appliance is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote A10 appliance is affected by a remote code execution
vulnerability in the management Graphical User Interface (GUI). An unauthenticated, remote attacker with access to a
management interface can exploit this to execute arbitrary code on the affected system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.a10networks.com/support/security_advisory/acos-agalaxy-gui-rce-vulnerability-cve-2020-24384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c6fb2cb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the fixed version mentioned in the vendor advisory, or apply the hot fix or workaround mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24384");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:a10networks:advanced_core_operating_system");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("a10_acos_detect.nbin");
  script_require_keys("A10/ACOS", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

# Lacking hotfix or workaround check, so require paranoia
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_info = vcf::acos::get_app_info();

# 4.1.4-GR1-P4-SP1 is 4.1.4.1.4.1, 5.1.0 is 5.1.0.0.0.0 - if any of GR/P/SP are not mentioned, 0 is inserted.
constraints = [
  { 'min_version' : '5.1.0', 'max_version' : '5.1.0.0.3.0', 'fixed_version' : '5.1.0.0.4.0', 'fixed_display' : '5.1.0-P4, 5.2.0'},
  { 'min_version' : '4.1.4', 'max_version' : '4.1.4.1.4.1', 'fixed_version' : '4.1.4.1.5.0', 'fixed_display' : '4.1.4-GR1-P5'},
  { 'min_version' : '4.1.2', 'max_version' : '4.1.2.0.5.1', 'fixed_version' : '4.1.2.0.5.2', 'fixed_display' : '4.1.2-P5-SP2'},
  { 'min_version' : '4.1.1', 'max_version' : '4.1.1.0.13.1', 'fixed_version' : '4.1.1.0.13.2', 'fixed_display' : '4.1.1-P13-SP2'},
  { 'min_version' : '4.1.100', 'max_version' : '4.1.100.0.7.0', 'fixed_version' : '4.1.100.0.8.0', 'fixed_display' : '4.1.100-P8'},
  { 'min_version' : '4.1.0', 'max_version' : '4.1.0.0.13.0', 'fixed_version' : '4.1.0.0.14.0', 'fixed_display' : '	4.1.0-P14'},
  { 'min_version' : '4.0.3', 'max_version' : '4.0.3.0.4.0', 'fixed_version' : '4.0.3.0.4.1', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '4.0.0', 'max_version' : '4.0.1.0.3.0', 'fixed_version' : '4.0.1.0.3.1', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '3.2.5', 'max_version' : '3.2.5.0.1.0', 'fixed_version' : '3.2.5.0.2.0', 'fixed_display' : '3.2.5-P2'},
  { 'min_version' : '3.2.4', 'max_version' : '3.2.4.0.5.0', 'fixed_version' : '3.2.4.0.6.0', 'fixed_display' : '3.2.4-P6'},
  { 'min_version' : '3.2.3', 'max_version' : '3.2.3.0.5.0', 'fixed_version' : '3.2.3.0.6.0', 'fixed_display' : '3.2.3-P6'},
  { 'min_version' : '3.2.2', 'max_version' : '3.2.2.0.8.0', 'fixed_version' : '3.2.2.0.8.1', 'fixed_display' : 'See vendor advisory'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
