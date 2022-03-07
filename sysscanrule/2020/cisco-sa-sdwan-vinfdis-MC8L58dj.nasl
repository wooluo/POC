#TRUSTED 1a726b4c857bd084fefc0b671badf6ec05da376d497c0904a5ff66a25071ff5cec2d3108f6fc0dc727925504bf42503d8132f6cc2ce4da09b2fedcda7530b1ad7a0e5e1929df0380a83201f8fcd786c1f8d43f01de18342210c210c3d0f7b3a5928060da7357bf99c6e70385ab285adcc60e4731b7e4bc5c58f62fc277e91d8a0be6407075d8583e68c02f9b2766e4404067a471f485e9622e78a5c1f59ab7b1df036789ac2f03959c5d19a9a29d4fb1ade2b0790bc2c5f37542bd56604dc663945ad2e2be35fc32b3821329937c6f33c2355f6dfb0a417656ef8afe1e5ace45f4af11d4a4e21614f802809dc68582e4e15849aae04e666183132204bf6bc323f44f4fafa45cccfab907fb27a15d729507adec477b392ba6eb7c7f020932ed5b0d689b1a3559249d1b03a40ad2388e236e02a8153553a0a6d637b654afd68b3c72f850b65678288f8911106ebd6a97ca6fd371a15bcce5e5e8d03cb9fd062ae58c7d539e0a08bc2710e6bca4a00cf98b8a175d15be9ceb0483b1e5492e8ba6106cc78c999f1fcbe499f411d7fa7a4bbc13108ffafaaae28abc66d57638eb3aaa714232a30527b8fb479d66771e2d22aa28592415d8c8e90d141f66b0975b932dd7b5bdce254407691add124f091c1f28895de0b58118a2c60393fb200e890904dec04e1e64ce4ece0b3449a86aaea5c69f1118f13f442b0cf2614d7f860b4961
##
# 
##

include('compat.inc');

if (description)
{
  script_id(145501);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2021-1235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs11276");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vinfdis-MC8L58dj");

  script_name(english:"Cisco SD-WAN vManage Information Disclosure (cisco-sa-sdwan-vinfdis-MC8L58dj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an information disclosure vulnerability due
to insufficient user authorization. An authenticated, local attacker can exploit this, by accessing the vshell of an
affected system, to read database files from the filesystem of the underlying operating system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vinfdis-MC8L58dj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?321da1d6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs11276");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs11276.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
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

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'19.2.3' },
  { 'min_ver':'20.1', 'fix_ver':'20.1.1' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.1' },
  { 'min_ver':'20.4', 'fix_ver':'20.4.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs11276',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
