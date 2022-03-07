#TRUSTED 0de713ec95d76f7df6325a55dca590ea906149a028fe8ff0dbb8106dc50c4e83a802e4e6820c57fbe26b16922626760671d52a809cd338f19f5f144015114fa5b5559f859ae4a8bf8721f2639328ba233854734e28539a617c501803bee94719ad76b2a42c2887a7aadf0296102c195ee5169fbddacf35252c24212b9366dd432bc44236974b9c7183e5631bbb5a152db17f914ecc4b6eec3e87eee31d009521df59bb088d0a9c960bceb63912f523f6d5781738e99abeb75f94b02e4782010e39e377e8c13d4558003dab7331ce4d343b3eb4cedf9b72df4b41c670433924a8aadec5604e88d8b70b669a2464aa08f94a2bfea932fae0b92ae5f64ce7659647c4cae94fc06b2254c9a0228165841ef8ccddba82cd85bf05606a06612d30d787a11c557dd22732071513fded98b35e5fdda7c9c80dbb64a267040f6ecf8d3db11e17bb6bf7a447897be43a79698145cc8fae33af121b07763dfd40b8f9745b5557026e1b020c4a20db29a03e19eee2a2fdffc8d775838419081a93c268d32758902778a0db51b4e8ae5ce85fd76bcfd38fe3b338fe583eefc94d2a1137bb05fd8ff3673ddc7dcacd7e074d716d84c3305ccf5386de544449ba8d69be5ab68db51b76c4c0071ec1fa1ed034e5cd80cc454db8d491f43496b2c94b9b71f6637e79a4771a3f9d22cf1fe6c3751df31be69235ef7a56ffaab18408b787f46c5bb0b0
##
# 
##

include('compat.inc');

if (description)
{
  script_id(148104);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2021-1441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu61471");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-iot-codexec-k46EFF6q");

  script_name(english:"Cisco IOS XE Software Hardware Initialization Routines Arbitrary Code Execution (cisco-sa-ios-xe-iot-codexec-k46EFF6q)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-iot-codexec-k46EFF6q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cc07188");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu61471");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu61471");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1441");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if (model !~ '^ISR1100')
    audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.9.1',
  '16.9.1c',
  '16.10.1',
  '16.10.1e',
  '16.11.1',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.1za',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1r',
  '17.2.1v',
  '17.2.3'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu61471',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
