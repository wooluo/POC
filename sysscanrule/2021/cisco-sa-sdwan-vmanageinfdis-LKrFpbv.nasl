#TRUSTED 7670980b3c92cb478b132880d0cff0a2856782437038c9bcd1caf23b2af5d451aac946eae321d9978c80befc4e6117de4c88012f31208c98b8420b8b9eabcec3b934bb42c8e17bd62f1089dca8e2fb8c6311b402cd2566ba915611bbeddafda41787203cc710e95a6cc9343e562fa3e72caf08b623ce37695489b02bf6fd280d161097f124f7a2b92c65ea38cc9e6174308a55e3130218f8db4a4d80bfcac36d39d668e692a3782407034991eca3d03c8dd9db880f1209d14263372766ec8fc818edf39843356669f9275367d6a31afbcba2a6fa00654ef8d398a44e57445950687b980c3a0a61b172733830e115ea26a0fc012f0fcd80ee97095c37f2bf3408dc16baeabf3d372032633f234428135cc15e5c7517671a2041ec48c268c21b3dad3ea5b3363d705bee51dd7043b3a604bacc9f3b4b7b4e6b8bd5acbc7e84782503a1e358dcb0d745d742aa3731b5316538d2f9b96ec44fb514543593c49bd2119b362ad251da8287591604e5d3d66d4fec62575130326399c7455a9b475bd7532e717eb542233a0ce9b6cf35f818bb06b8b8838546187499a66467bba0cd1459340266c4d3c7361a08f454ca5198c1e7cd09baa4cc39e3e51b9337a2b01d79491cdec630ac4d7414491207a5097fa85105556716f23685e7895fbbc2a360e52eee73d534c4d1a6922efcdd02d9e42d01481160aaf71aa280edb50be7c9e8db53

##
# 
##



include('compat.inc');

if (description)
{
  script_id(150339);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/09");

  script_cve_id("CVE-2021-1535");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw11097");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vmanageinfdis-LKrFpbv");

  script_name(english:"Cisco SD-WAN vManage Information Disclosure (cisco-sa-sdwan-vmanageinfdis-LKrFpbv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by an information disclosure
vulnerability due to absence of authentication to view sensitive information. An unauthenticated, remote attacker can
exploit this, by sending a crafted request to the cluster management interface of an affected system, to view sensitive
information. This vulnerability only affects vManage systems in cluster mode.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vmanageinfdis-LKrFpbv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e840bd43");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw11097");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw11097");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

# We cannot check for cluster mode
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw11097',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
