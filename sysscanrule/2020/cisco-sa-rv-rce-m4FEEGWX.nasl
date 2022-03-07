#TRUSTED 745d79f960b6af0af83b1b2a12a756156d6531bfdfaec989f6e38f2923802d2c7485b4cf74fe6407f058cbe454eca50f40c3387d457b8362d64d13da2a05a1967457b8149326b4609d6f58c3d2f5e774fb269ba2e4d071d1956967a6416a3ac21cdd55a0f3a8a48a1124d2b9bb14e933fb3258f4a33f0a8df24a80e7ca5b57affede2d37cab1bade4f6a5af33dd4ae9a5b9279d25d2e52e62ed63ca74f39e4e02e07b1a1f48439229aeebf119d3054ed95af228f33660dadfb6684d4b9787dc7449f507095ffd31c9e5322494cb8f31f3591fa9db09ad70dc1ce8f90c1fd7d4860fd8beec9f9a012f092562d951db4ed023544fe04de04c27e5d9ec8a5c1fce9456bd909ef909abb47e5f408f3481b7b82becec1e2006d7cdfb962c92fe2a2b69b3ecc0f8bc9dc6fa4f6d7701699feafb0e02aaf590673e381c4e6d08aacb72f385871000cda464997376cca7849085caa5b3c34ff1a4b27cef655129f6d42cab1502e886c9e8757aa332a133bb374c5b54739172c71a9d775b57597e24f56234f66a2f285486615ea7f0018937b2e86c60adfc76fe7a7ae03058ef7872549ef3599b68f3feef1c9c9459afa93cdb18f460126c08fccff87de96fc8d38c041a20ae0a86d97ed5df168014b57529beebdaf1d9be7f713176c6a48c0ec665a95ab73f1f5918425bf07820de1451f817250a519b3d49a6185b3fd24f2466329f276
#
# 
#

include('compat.inc');

if (description)
{
  script_id(139067);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2020-3145", "CVE-2020-3146");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr94660");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96222");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96232");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96242");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-rce-m4FEEGWX");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV Series RCE (cisco-sa-rv-rce-m4FEEGWX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware 
is affected by an remote command execution (RCE) vulnerability due to improper validation 
of user data. An authenticated remote attacker can exploit this, via HTTP requests, to 
execute arbitrary code with high level privilage. 
 
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-rce-m4FEEGWX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3bf0372");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr94660");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96225");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96232");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96235");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96242");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

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

# RV130 & RV130W affected version < 1.0.3.55
models = make_list(product_info.model);

if (product_info.model =~ '^RV130($|[^0-9])')
{
  # RV130 & RV130W affected version < 1.0.3.55
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.0.3.55' }
  ];
}
# RV215W affected version < 1.3.1.7
else if (product_info.model =~ '^RV215W($|[^0-9])')
{
  models = make_list('RV215W');
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.7' }
  ];
}
else if (product_info.model =~ '^RV110W($|[^0-9])')
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

#Reporting paranoid since Web GUI check determines if vuln or not.
if (report_paranoia < 2) audit(AUDIT_PARANOID); 

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvr94660, CSCvr96222, CSCvr96225, CSCvr96232, CSCvr96235, CSCvr96242"
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:models
);