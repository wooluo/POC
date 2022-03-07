#TRUSTED 2cdf50fc8a94f596abd5a7192d326d70e01660fe9c7c2a1eb72574af76816aad8b791e02b8033f7d9dd113a3e19d46eef1449f73a44b474e89ea43f64ba8d7daaf7717c460d8eacc3911af5d96e726c5193ba60c2a683ab342c248c826974c4774c36dd81958ae753940b781c9f1a4aba63f25d3d4d6df2e4b0cca647fac5252be8f4db3e3a2f3ae2e2b53cc1ef82941ca0ef238f6e3cb46ed94890668d71390e7819e90ef08609305f41e9abfd21461a0ca050c6b6c99ff56005e4f603f975a23a9885abe7bb67ea3d724e5c03d86d8e3d2f036cf2d83ddae23bb127b7a638dc661116a60c92cbe296e1c083d45de970d8f51eecac1f6468e0737f1f4ba1ff1ce9c96176bc6b4c94bd73f32a011c1bec89d5521be31f266fb04bc9fa1ce85c5ddc9ba4235d752b489d5223d47519048d010ffa4d454e8b96e4943949e84664dad3e97b36820f14935ae24b068ad545a64cfc583c4beddc795d9ed2ba98aab2589c1ea2623a6d2d8483261913a72001f3e6bcbec0e712ed65c8fcb31d1a9dc178c0664138ac395876c3f70369c522a28ceab83fd45f8251c5cedcd5abb0dc7cb85879e32c256e485c3f4977b75867d8b6bfe16bb526c947fc89153875937defbcb4289d81c8508213f635365f9275c8f9eeb301db8e7a48162f47299b5efa5acfc2a794d9fa41070ad0029403b8d8493d257cf947a7fb83ff57a552be5e841dc

##
# 
##



include('compat.inc');

if (description)
{
  script_id(151187);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2021-1259");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi59632");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk28549");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-pathtrav-Z5mCVsjf");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN vManage Software Path Traversal (cisco-sa-vman-pathtrav-Z5mCVsjf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by a vulnerability in the web-based
management interface due to insufficient validation of HTTP requests. An authenticated, remote attacker can exploit
this, by sending crafted HTTP requests, in order to conduct path traversal attacks and write to files.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-pathtrav-Z5mCVsjf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85975068");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi59632");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk28549");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi59632, CSCvk28549");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.2.0' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvi59632, CSCvk28549',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
