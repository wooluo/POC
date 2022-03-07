#TRUSTED 01b435bc0ff803a77a13619aec80d61caa3beeecdba167d3e4ff6ef760c78e41bc143137e486f07b6c54d639a21c93e1d465f6f58e8745b57613b16a14631884c7351be719998d24e61aabe8258cf74d495fc08a072c415613fc90c089deac5da73c46986d1a4a21d4c3854d995613f64416b6d93720581776bbd9620a6b2344b2e4ce932b90f580ab25b4d000af5f1df6a159f38e04ffeb8c4d69c9750001aa5281b1305ed4e954d01bf30f49347f6b09b855b96a8787f381f73e164c1b21d427999ee7bbf86fdbfbda08009d9fdae730e42a826965d6ee411e994bfcc76428a8278cd6df820f946ee3eb36bca5ba542f72ec04d4fcc1de6a86cb0246c54ecca40cced678c2ee669155468d0e238b9dab3a2af6d5a56c3e164acb08b78f7be5c2beabe0e670933f5a3a9bfaad88b08a5a280de50eacbbc62fef57ee95c2e519d1e589653fe4ee43cab1dcb328cefce2e6513b48042fea3dc981ae88a856d127055f3b511cda7b1a4fcccbc9955fda83e8fd5bd092bb35b03f9d09cdcef8442b744f770e7009a6f95a81f41c87ea5593fa2c4fc4c278cb151532a5575ca7eefb8b0b918c68d433f627678cf5adc00060bac26bd3195f96433c3a065b43556ae8aebda24444befd30aca8efb9b8e6d188a7360b7e054ed0d61adf2a9b604b4b13b1f53b45df25b1e8a884555580c04a56b615b036fa70de0606b42aed77df0269
#
# 
#

include('compat.inc');

if (description)
{
  script_id(139927);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/31");

  script_cve_id("CVE-2020-3332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50846");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50853");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cmd-shell-injection-9jOQn9Dy");

  script_name(english:"Cisco Small Business Routers Command Shell Injection (cisco-sa-cmd-shell-injection-9jOQn9Dy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by a command shell
injection vulnerability in the web-based management interface due to insufficient input validation of user-supplied
data. An attacker could exploit this vulnerability by sending a crafted request to the web-based management interface
of an affected device in order to execute arbitrary shell commands or scripts with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cmd-shell-injection-9jOQn9Dy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?632564a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50846");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50849");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50853");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs50846, CSCvs50849, CSCvs50853");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Device");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business RV Series Router Firmware');

model = product_info['model'];

if ('RV110W' >< model)
 vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '1.2.2.8' } ];
else if ('RV130' >< model)
 vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '1.0.3.55' } ];
else if ('RV215W' >< model)
 vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '1.3.1.7' } ];
else if (empty_or_null(model))
  exit(1, 'The model of the device could not be determined');
else
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50846, CSCvs50849, CSCvs50853'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV110W', 'RV130', 'RV130W', 'RV215W')
);

