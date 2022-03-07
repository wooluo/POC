##
# 
##

include('compat.inc');

if (description)
{
  script_id(144950);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2021-1258");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu75418");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-fileread-PbHbgHMj");

  script_name(english:"Cisco AnyConnect Secure Mobility Client Arbitrary File Read Vulnerability (cisco-sa-anyconnect-fileread-PbHbgHMj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-anyconnect-fileread-PbHbgHMj)");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the cisco-sa-anyconnect-fileread-PbHbgHMj advisory. Note that Nessus has not tested for
this issue but has instead relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-fileread-PbHbgHMj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c23ec422");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu75418");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu75418");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1258");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', port:port, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [
  { 'fixed_version' : '4.9.03047.0', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
