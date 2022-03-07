#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124173);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/08  6:00:23");

  script_cve_id(
    "CVE-2019-10655",
    "CVE-2019-10659",
    "CVE-2019-10660",
    "CVE-2019-10661",
    "CVE-2019-10662",
    "CVE-2019-10663"
  );

  script_name(english:"Multiple Command Injection Vulnerabilities in Grandstream Products");
  script_summary(english:"The Grandstream device uses firmware which contains multiple remote code execution vulnerabilites.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is vulnerable and can be compromised");
  script_set_attribute(attribute:"description", value:
"Multiple Vulnerabilities in Grandstream devices.

   - The affected devices are: GAC2500, GVC3202, GXP2200, 
     GXV3275, GXV3240, GXV3611IR_HD, GXV3611IR_HD, GXV3611IR_HD, 
     UCM6204, GXV3370, & WP820.

   - A remote command execution vulnerability exists in the 'priority' 
     and 'logserver' parameters. An unauthenticated, remote attacker can exploit 
     them to bypass authentication and execute arbitrary commands
     with root privileges. 

   - A blind command injection vulnerability exists in the 
     'file-backup' parameter. An unauthenticated, remote attacker can
     exploit this to bypass authentication and obtain a root shell.");
  script_set_attribute(attribute:"solution", value:
"Update to the fixed version as per the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("grandstream_sip_detect.nbin");
  script_require_ports("Services/sip","Services/udp/sip");

  exit(0);

}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('vcf.inc');
include('obj.inc');

# obtain ports/proto detected or exit...
detected_on = get_kb_list('sip/grandstream');

if (empty_or_null(detected_on))
  exit(0, "No Grandstream Models were found in the global KB.");


# Flatten the entries out to get the list of URLs.
detected_on = list_uniq(make_list(detected_on));

# initialize... before chking / appending any possible results
vuln = FALSE;
report = NULL;

# what's affected...
models = {
  'GAC2500' : { 'constraints': [{'max_version' : '1.0.3.30', 'fixed_version' : '1.0.3.35', 'fixed_display' : '1.0.3.35'}]},
  'GVC3200' : { 'constraints': [{'max_version' : '1.0.3.51', 'fixed_version' : '1.0.3.57', 'fixed_display' : '1.0.3.57 (Beta)'}]},
  'GVC3202' : { 'constraints': [{'max_version' : '1.0.3.51', 'fixed_version' : '1.0.3.57', 'fixed_display' : '1.0.3.57 (Beta)'}]},
  'GXP2200' : { 'constraints': [{'max_version' : '1.0.3.27', 'fixed_version': '9.9.9.99', 'fixed_display' : 'this device is at the end-of-life'}]},
  'GXV3240' : { 'constraints': [{'max_version' : '1.0.3.210', 'fixed_version' : '1.0.3.219', 'fixed_display' : '1.0.3.219 (Beta)'}]},
  'GXV3275' : { 'constraints': [{'max_version' : '1.0.3.210', 'fixed_version' : '1.0.3.219', 'fixed_display' : '1.0.3.219 (Beta)'}]},
  'GXV3611IR_HD' : { 'constraints': [{'max_version' : '1.0.3.21', 'fixed_version' : '1.0.3.23', 'fixed_display' : '1.0.3.23'}]},
  'UCM6204' : { 'constraints': [{'max_version' : '1.0.18.12', 'fixed_version' : '1.0.19.20', 'fixed_display' : '1.0.19.20 (Beta)'}]},
  'GXV3370' : { 'constraints': [{'max_version' : '1.0.1.33', 'fixed_version' : '1.0.1.41', 'fixed_display' : '1.0.1.41 (Beta)'}]},
  'WP820'   : { 'constraints': [{'max_version' : '1.0.1.15', 'fixed_version' : '1.0.3.6', 'fixed_display' : '1.0.3.6'}]}
};


# loop through the detected_on (proto/port) assets
# obtain the model/version of the associated proto/port
# alert if matching the known affected assets
foreach port_proto (detected_on)
{
  model = get_kb_item("sip/grandstream/" + port_proto + "/model");
  version = get_kb_item("sip/grandstream/" + port_proto + "/version");
  if(empty_or_null(model) || empty_or_null(version))
    continue;

  # if the model is found, check for a version less than... 
  output = vcf::check_version(version:vcf::parse_version(version), constraints:models[model]['constraints']);

  if(!vcf::is_error(output) && !isnull(output))
  {
    vuln = TRUE;
    report +=
    '\n  Model             : ' + model +
    '\n  Installed Version : ' + version +
    '\n  Fixed Version     : ' + models[model]['constraints'][0]['fixed_display'] +
    '\n  Port / Protocol   : ' + port_proto +
    '\n';
  }
}

if(!vuln) audit(AUDIT_INST_PATH_NOT_VULN, 'The Grandstream asset' ); # is installed and not affected....
# we will have one or many ports... zeroing out...
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
