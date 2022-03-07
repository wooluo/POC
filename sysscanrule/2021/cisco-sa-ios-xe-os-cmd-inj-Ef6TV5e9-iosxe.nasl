#TRUSTED 9e71b169884597f8c860bad5381b081e02c4e341b6d03f0d2148ba28695299ba6f668c0d52f377c5dc2a3c434b81ea908e2641b7b61302ec06e952383daf6e0923026e99237c5e053674e21871974e168fd7536a77d5588a7a86942d4e6fd64ef00ae3af59ad23b25f337a81c4883cc9aff3907c8ecb3fee73f92c8121b9ef07199f3855a3879da3f0fe4b6354c2d56a70efed7a6df7af5d107c64ed9730a371de16126a5c4ed03b1c56383aa49ea97f851c2629c8317700eb0bd88a26c8ff1ffa0e1146d9d30f03e777ce1ef7b9216fc5c3394f4bc41aec1626c57292aeabfa6e697746dcd68490574d3623fe012f0d82f4e8fde0e224c1ecbc2130daeb419cd9911e708380b9a69617060fc377c12be7a44ac699ded3787dd029d2822cbea2d51d3fd16ad7409e136bca93959b4d01b16ca91503a84ec4005d7392e1be3e655e8130d1112f78d6639b1de7b9abc5789989ff49167b071526388f307d74f8c33369109711bc6ced69bcbe370bfa74f7fe6cb06ae8f1f61387cd442783016310dc1f8d731b2dd3a5c9d4bc803ad9bd83f1f1fd34a45508f681ae044d07cc78886ceb433a645f4a705e6f61c1fa5bc566e8c0a31612e1d89fa4f6b10e59dbd9c1a16c7cab6cc725b93d7751ee185da96acf8628f319407543195a74e39e1528cfaae98a67f59ecbcb5ae90cd58c3bbd2e1e53fc0cd6212113c1436c826171040f
##
# 
##

include('compat.inc');

if (description)
{
  script_id(148102);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1443");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu60249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-os-cmd-inj-Ef6TV5e9");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-ios-xe-os-cmd-inj-Ef6TV5e9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-os-cmd-inj-Ef6TV5e9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcafafe0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu60249");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu60249");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1443");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

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
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu60249',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
