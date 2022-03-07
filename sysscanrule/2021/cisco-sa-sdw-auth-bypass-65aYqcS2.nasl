#TRUSTED 4fc99d097fe24ee290e0b426697137763fc124c5fa9a1a372cfe281541a1223a756bc3bdd8a4c508d015f481551374638e5b6ca0ab7b2d35ef980de162ea13923c3a8ea3b39d193f5dfd77b8ecad6914e2ea231592d34f47dbb2bd8de216061efa16db8f2353691d6157bc25dca3e2f35e69fc89a2d663dd25ed6665180a5d65d7beb53955996b7bc3078b6d28bc040bf1f7ca5165aefb14d29e4f0335838352e40c61126d1c3a86bdb164db9b22d835c6a310088ab33b7c7253f4649a96a60a34959ebc357db1f9d8fc0d7b829237162bd8479bf13d7134e8019b024376a27ffa9a120aa94c119bcdbf8002f80f9839348b3fe63d54d5ab0dad0c7d91cf4e86846fade1da6a7fb68ce064a89527dfcb41d265840046d0ddcd6f8166beddf38dc518c2f2ef702b5cadc864fbe26809c53da74d56a691a14ad8c7c540c1c66f91be150ef5a4d53281a6bcabfabcec3e06b81b9dadbb95997fbbf4151260e68ddf5f24164a98e8e5b65825dd7a4e89cf168c48a1d971a0d4bef6d82d4a2e071e89e6b41633218da88bbbeee82bc27a3dd3fa7e78765819f8c2cdb8b8aeeb282a29a855cb215894faed0a2c99a630f25d5aaa2d2f7327501157b17c1d8d445e6f10a544378567dd06b5fdaa0c98630f43a231f0904fed2cea87afcb0c4f5bd4081d3a9fdbeb37fce6dd9ab22d0f7e2e8bfccefe6b0f91afd1c35757bcba45c963b8
##
# 
##


include('compat.inc');

if (description)
{
  script_id(149330);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2021-1284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69876");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-auth-bypass-65aYqcS2");

  script_name(english:"Cisco SD-WAN vManage Software Authentication Bypass (cisco-sa-sdw-auth-bypass-65aYqcS2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability in the web-based
messaging service interface. An unauthenticated, adjacent attacker can exploit this, by sending crafted HTTP requests,
to gain unauthenticated read and write access to the affected vManage system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-auth-bypass-65aYqcS2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80f54587");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69876");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69876.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvi69876',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
