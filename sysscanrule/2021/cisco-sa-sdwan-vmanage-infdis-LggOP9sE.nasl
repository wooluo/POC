#TRUSTED 17047ce0564c4129e36157a4703a05ab1161a9e184e6c29a152415ab59db506038340724aba17638492c789bbaf25e443f46020f5a4cf76d893dacae984cf27e677addc6643753bd6600748023ea69a7045387f95f47ee47c4a939773a2d388367505851ae77399279d35206570310496d879867ae1c2bfc30745237f33172a3fbbe304b2c11fbdfd35ab0a668487d377b98b822031226b3e8926e0010db177a441e247d36737351b696e165dc9722c386780d300b1fecf9e754c2ee3a608a0a8ed08cd5ff42757db209d3f3b87fb888a152f3911ccfdc47fd53ebc6572121d800b17572cdc6776701ec789339087ae91a6162b12458e3769a30071c7dbe34e89c54c42baeffbf1d3963cc2078487e39440fcc593c58fa22f3481610bbe11f372b4d1cf3f03eca587747b4eb63e726b86a57d0da42262f65c8e8a40f040a5cd5b02714b6f4d5c4bf00ee2fade04e5155d654ca674d7f5b0ed9e8ec711aa5011378d9abbd872b05146721a4f3a80ef6eeaa4c909e5a817bed505f4e6082eac70669ffa1c19e9a85429142e80f45a5d74aa6cce1ef6d2b33fcb0b007c1d0dc94babf0936a3b926d0186593531a2e7029cad24474ced099865e9b497dc28c9f00bf2316040fd6b0a2f1784e9c4eaed8999fa50c88928db0e9428060cfd2805d6d731efad7e9042efd64ac5c39dcee803ab790a94310552fdf1879c38d38ee0fdadb

##
# 
##


include('compat.inc');

if (description)
{
  script_id(151916);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id("CVE-2021-34700");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53695");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vmanage-infdis-LggOP9sE");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-sdwan-vmanage-infdis-LggOP9sE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vmanage-infdis-LggOP9sE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fc87199");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53695");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw53695");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(522);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
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
  { 'min_ver' : '0.0', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvw53695',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
