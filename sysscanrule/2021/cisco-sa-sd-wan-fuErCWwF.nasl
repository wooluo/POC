#TRUSTED 80a99a94369f83d390b8ae473b3db151c9b65829e4fb753707599b37b63bb9bb1eaf36d7ddb1158301c62af588b5da27f0788e158e7a7c939147c519bb5ff3b66bbd04d41137ab460157a990152082551f917333b9479044d75dc6bade5473a3df4b730d234fe15e7604784ecb7cbb10fbdf7eefcbfaf89bc218bd58c1c347c3462597d14205f862584c6a54a34e7041ca7fa754df99fbefccc96e10861e7353858ac4e20654b14967042cb78dfcff303181a3f4f2ff21d084abb9e5694b322f8660acd7dcd2119bd91fcb1c53131db5a1329f5c0272e1e3076d428fee49bcd62dbefcf94049f0129b8eb06d20f76c806d72cc4728ba9059b0f0e36a64ad4549586adb04f9fe025057c82e76120c580ee501909eb1d44219383d010a711f7a4f8daca6c6e0ffd9711ea2e974b89033c892ad4dab4c643590c7ae7c7320bf5461dc7a59ae980cd5e2d458c5abd5085b38ad3a7c57ee0ead810b8852e2c0aaca5b383d178aa83ffca3c06b8d645b968bcd5009e883d40bbf51d57bfafd35ee86e51b2fad0d852423014b117afa1150096a8add5d4a0e214aef1ca31144797dc149799a7efaf5c7de6fd50cecd088301b81ab503d9250969f9605838d676e314c9de45ad8a5e277595ad3f151006eeffd1b4cfbf3ca37821c2205c5b8af24170c2a4ae9d50775567c1b44a5f2747235501171198443ed0dc16859ca05ab4fbd4581

##
# 
##


include('compat.inc');

if (description)
{
  script_id(150141);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id("CVE-2021-1528");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx49259");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-fuErCWwF");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation (cisco-sa-sd-wan-fuErCWwF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-fuErCWwF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c64e7897");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx49259");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx49259");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1528");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
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

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx49259',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
