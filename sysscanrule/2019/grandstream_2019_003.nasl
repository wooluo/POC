#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123520);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/08  6:00:23");

  script_cve_id(
    "CVE-2019-10655",
    "CVE-2019-10656",
    "CVE-2019-10657",
    "CVE-2019-10658",
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
     UCM6204, GXV3370, WP820, GWN7000, & GWN7610.

   - A remote command execution vulnerability exists in the 'priority'
     and 'logserver' parameters. An unauthenticated, remote attacker can exploit
     them to bypass authentication and execute arbitrary commands
     with root privileges.

   - A blind command injection vulnerability exists in the 'filename'
     and 'file-backup' parameters. An unauthenticated, remote
     attacker can exploit this to bypass authentication and obtain a root shell.");
  script_set_attribute(attribute:"solution", value:
"Update to the fixed version as per the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
  # https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=23920
  script_set_attribute(attribute:"see_also", value: "");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("grandstream_www_detect.nbin");
  script_require_keys("installed_sw/Grandstream Phone");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include("http5.inc");

port = get_http_port(default:80);
app_info = vcf::get_app_info(app:'Grandstream Phone', port:port);

models = {
  'GAC2500'      : { 'constraints': [{'max_version' : '1.0.3.35',  'fixed_version' : '1.0.3.37',  'fixed_display' : '1.0.3.37 (Beta)'}]},
  'GVC3200'      : { 'constraints': [{'max_version' : '1.0.3.51',  'fixed_version' : '1.0.3.57',  'fixed_display' : '1.0.3.57 (Beta)'}]},
  'GVC3202'      : { 'constraints': [{'max_version' : '1.0.3.51',  'fixed_version' : '1.0.3.57',  'fixed_display' : '1.0.3.57 (Beta)'}]},
  'GXP2200'      : { 'constraints': [{'max_version' : '1.0.3.27',  'fixed_display' : 'Contact Vendor'}]},
  'GXV3240'      : { 'constraints': [{'max_version' : '1.0.3.210', 'fixed_version' : '1.0.3.219', 'fixed_display' : '1.0.3.219 (Beta)'}]},
  'GXV3275'      : { 'constraints': [{'max_version' : '1.0.3.210', 'fixed_version' : '1.0.3.219', 'fixed_display' : '1.0.3.219 (Beta)'}]},
  'GXV3611IR_HD' : { 'constraints': [{'max_version' : '1.0.3.21',  'fixed_version' : '1.0.3.23',  'fixed_display' : '1.0.3.23'}]},
  'UCM6204'      : { 'constraints': [{'max_version' : '1.0.18.12', 'fixed_version' : '1.0.19.20', 'fixed_display' : '1.0.19.20 (Beta)'}]},
  'GXV3370'      : { 'constraints': [{'max_version' : '1.0.1.33',  'fixed_version' : '1.0.1.41',  'fixed_display' : '1.0.1.41 (Beta)'}]},
  'WP820'        : { 'constraints': [{'max_version' : '1.0.1.15',  'fixed_version' : '1.0.3.6',   'fixed_display' : '1.0.3.6'}]},
  'GWN7000'      : { 'constraints': [{'max_version' : '1.0.4.12',  'fixed_version' : '1.0.6.32',  'fixed_display' : '1.0.6.32'}]},
  'GWN7610'      : { 'constraints': [{'max_version' : '1.0.8.9',   'fixed_version' : '1.0.8.18',  'fixed_display' : '1.0.8.18'}]}
};

vcf::grandstream::check_version_and_report(app_info:app_info, constraints:models[app_info.model]['constraints'], severity:SECURITY_HOLE);
