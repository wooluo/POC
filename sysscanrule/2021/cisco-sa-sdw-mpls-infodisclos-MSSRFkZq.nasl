#TRUSTED 79325736e4baf22a5f7c57ec3837ef5430f35a04624ba5ccbf67bb9bb1ff9a27d3a42e4486f1fa25e311917c7febc08129f58fda353a72ab659d2be71d38a7f29b2ebf9728165c2f96f631a5f2906c1bbc8a42814d28dfd5a5cb89da2989db805eaef1a5b6c3a96f1fe719ec44e9dc896caa5dca02542fc333adf75b4fefa2c8c4f9d9dc4248be80e0b551f46418902e3abd4bf8d8a3aded104a99e10273f6cd0d298af18a84389a632b0a089def85c4f9f744af356b582bc76e054a25152e2435e1a368d11eb1f37c545f6a19f8fbf49f810c129bc22b8b10221eb80c3b9d5f72b0792e8e8aa7d3c62b2160b277275636a60fd39adafc2b146c1faca97de3899b9a3895867b7f82b1d2df56fcbfa23c3aedc599abccdf97882d601107c859c38d35d0ae418363c573192ebebb98a5235f2497caf1f81514ca8d834e634eb441cc8f3c7fe43af4699fb0aed124df8a977894e3a2ec45a376bd28f021b5dc2225de5fe7ba4041c2cea58c3fd35a4dd9562e2f4c0293aa1879763794c81a6b855bae86b2e975f8b485d82aafdd48c97f50c4a46f98c98beb094d226008d8a3c7817bf6e4d82b155969b03a6f27df80c6d6bd9ca9c2c14f113d0a97fef2d18d79fba08cc92b69b32a585aaeaff6d845d03b32193440a5b0a52aee740a9ac96ca909ef893c04eac67b88eb5dc27f9a4e944e6d1fd6837fbca647271de8a535cb8990

##
# 
##


include('compat.inc');

if (description)
{
  script_id(151915);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id("CVE-2021-1614");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28403");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-mpls-infodisclos-MSSRFkZq");

  script_name(english:"Cisco SD-WAN Software Information Disclosure (cisco-sa-sdw-mpls-infodisclos-MSSRFkZq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-mpls-infodisclos-MSSRFkZq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6a12dcc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28403");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

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

var product_info = cisco::get_product_info(name:'Cisco Viptela');


var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '18.4.6' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.3' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.2' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

var version_list = make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu28403',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
