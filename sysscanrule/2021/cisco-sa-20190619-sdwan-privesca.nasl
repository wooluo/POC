#TRUSTED 27a816d6bd9f98eb70cd594b321aa937f10ebe4fa3831a8b3a3928654b428d81742d5d0d170747590e7a7a28ab712c90ea5dc161112fd6dc6196b928ab00fecbed4bbfcc75278c76ab7147f9235d5a11514f6ec7b1f1b80c54316ccb5bccba3b897513d9820edad1afb4d787326b1c5b60db44414a7b8a72d7336b3dfd768a25d5d7a37d2093ff9231f109a6e793a58f02e4d7f2124c13d7d0cfad650fe4351011b4184faf7655b7cae99f50422a4c8736f8500d7180266f9694a89dc2193d57dc2cfb35f776a19208c635905e065835c1573e733bf1f2b64c8aaff31db360292c6aa552039b395de3f2efc09a9e83e415f85aa0eaadf0742eeb0234042df399f1aac2cb7cabd7cc9e5dcb58f4503200fcd61b8e9cd6f508584d1d795729b97897c471be4372cd1309637f2e1559e81221e1aa8ed4794a540bbc7aacaae09ff8b1130c8ec755b2b0b4aa13fd001bc021bedd6c85db4b80fb8ff7d4782dda7a1fa1c9bbddbcdb0227dacf48e5df5b72f3ff9cab5ef8675f5bca21e5c5739a3c045ba862752d8eb8593b44154d17de3ecbb8e9a036b2867a98dcbcf210a89c336c88ed756058a887269c8f2a7fc3098373eedae9709b59385732fee9f99561658d4b65cb641d8e3b7b871d4c9683b1bf4559765a51a604f67e6e5413f1d8659743055ae777ba2b4f8ef6d55689720a59464aaae9ed8597426d26b53a2ee6bf17f1
##
# 
##

include('compat.inc');

if (description)
{
  script_id(147878);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/18");

  script_cve_id("CVE-2019-1625");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi69756");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190619-sdwan-privesca");

  script_name(english:"Cisco SD-WAN Solution Privilege Escalation (cisco-sa-20190619-sdwan-privesca)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution is affected by a vulnerability due to insufficient
authorization enforcement. An authenticated, local attacker can exploit this, by authenticating to the targeted device
and executing commands, in order to elevate lower-level privileges to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-sdwan-privesca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83d43c6f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69756");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69756");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1625");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',   'fix_ver':'18.3.6' },
  { 'min_ver':'18.4',  'fix_ver':'18.4.1' },
  { 'min_ver':'19.0',  'fix_ver':'19.1.0' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69756',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
