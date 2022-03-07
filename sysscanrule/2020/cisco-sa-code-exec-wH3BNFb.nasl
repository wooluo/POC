#TRUSTED 7cfe1a72611e03ab8040b7f393efe268f963fd849f617a90d6878245761b0339136eff27f42c0301aa879da66f2aa1301515273d7d48017e86c7e9e77b87d16e461df7503a46d84e58efc63db22c21b6b94e4df9c6830aa14de7c5e73b406b0f3ed08462df9ae4268bcd71eaa6b33d3b25100ef493b8511d230b222842972c9e28e8522621f2367b6b20fcf1ae791a9847e89adc3ee37590b1ed259be7af79812a3c063795605468653abc78db6642fde85598fadf27fa130eafd4912b0bfeeb9835f725b4dfb18a6ee9c8218b6e802744267ac34a42019ad13f20392e997836095957add0cd19ab88450f77e662466e62afc919873685ff435102d24b614b1bb9f1581e34d7dd46b91e24879e31566311e07ad6eea325436388e45ac6a9481c46fb68aa4e4a3deb1513e573e7fc5a19a9524bd1561c7f49ed8e08530c45f1510040a1842c3ac86953a509467032f284bdb80709a0e309eeafa5fd9d83079ef919f80a25fd32e5165a9d202fc18d282bf00dd5e0e052511933ab8a03024597ac0702d3c17d8ca3172b6837454566efb1af8adecf72b7dae94470d8f482ff1cc97bc15d4bd9b600905e5a5ad1c6e1ba256a33b091297c5f04f4ec3f5d30715c9edd36040b36ccd02eab8c6f5441c1dee25b9c7fb3cc35013163709f93f51e3dc1b878c15465f3851b278af2e2fa028956c6b7f4297d9975026334cd771d85700a
#
# 
#

include('compat.inc');

if (description)
{
  script_id(139035);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/29");

  script_cve_id("CVE-2020-3331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50861");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50862");
  script_xref(name:"CISCO-SA", value:"cisco-sa-code-exec-wH3BNFb");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV Series Arbitrary Code Execution (cisco-sa-code-exec-wH3BNFb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is 
affected by an arbitrary code execution vulnerability due to improper input validation. 
An unauthenticated remote attacker can exploit this, via maliciously crafted requests, 
to execute arbitrary code with root privilage. 
 
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-code-exec-wH3BNFb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f49a149b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50861");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs50861, CSCvs50862");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Device", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
get_kb_item_or_exit('Cisco/Small_Business_Router/Device');

product_info = cisco::get_product_info(name:'Cisco Small Business RV Series Router Firmware');
models = make_list(product_info.model);

if (product_info.model =~ '^RV110W($|[^0-9])')
# RV110W affected version < 1.2.2.8
vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '1.2.2.8' }
];
# RV215W affected version < 1.3.1.7
else if (product_info.model =~ '^RV215W($|[^0-9])')
{
  vuln_ranges = [ 
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.7' } 
  ];
}
else 
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50861, CSCvs50862'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:models
);