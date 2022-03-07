#TRUSTED 0b2a5f525a44dd1bb746a5829c6f3d22b2b15e3ee3c6d5cc711cfd1e278486e78fe0f706384d9f09ee758de64adf7d68536aded6f2a530767b7b50c3c9f0d557311edcde13400521b508f815f49aaaa6dc7c14f30696faddcc1cde1b46c6c5240fd8d2bee4cdd88860ce7e5a9af5b28e4f0f2051a1597f97ce04e71a71fc2237af431df1099592e87bed0b93ecb228dc17de1d22e57434d6fed3aec2a3be47d2c47cf20dc31eadb31d0e7e2f2e4595ba430e0cd7cd0ddf6a14102f01a9f8881693650be6d232795b9e91343f7041001b7c87d79797f91c96827237e25d6df1350839f9b3064d781ea7d805b4ae0df8d534e498ee1223d72458694ee0658926a31c8e184acd48467c0588081deea09f3135601b9bb1ea842aaa31e0ee93b2b1f377aead294d7cb86bebbe944d995baa4ab80ec35cdfa7d12605f78f7bc0274fdaa1edcb9ffc5d63d335bf17a94029eb45e34d491619dfc1c38becf926c3bf4070faec10c8fd99ac263ae8827f99601ea4ea27b22356424e54ca93aa48c613a22dd7571d5680bbd4d328b3dffbdbd9436b156a88622a6014a42962b3c26042e394621554e027fba15a2d005710ab020712a721c5a7731b457c6320a8ca63e841fdb255c5289d0ae4423325dcf5bf8f3fed30e0ec75244ef9f622fd0a7093be772c625749ced9401fd45f2f60786972ea23644ff316160ccd8eed277b7450d53ad9
##
# 
##

include('compat.inc');

if (description)
{
  script_id(148124);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1287");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw65031");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw65032");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-132w134w-overflow-Pptt4H2p");
  script_xref(name:"IAVA", value:"2021-A-0147");

  script_name(english:"Cisco Small Business RV132W and RV134W Routers Management Interface RCE / DoS  (cisco-sa-rv-132w134w-overflow-Pptt4H2p)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business Routers RV132W and RV134W are affected by a vulnerability in the web-based management interface.

This flaw could allow an authenticated, remote attacker to execute arbitrary code as the root user or to cause device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-132w134w-overflow-Pptt4H2p
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a1083a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw65031");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw65032");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw65031, CSCvw65032");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(121);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv132W");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv134W");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:rv132w_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:rv134w_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');


if (product_info.model =~ "^RV132W($|[^0-9])") # RV132W
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.0.1.15' }
  ];
}
else if (product_info.model =~ "^RV134W($|[^0-9])") # RV143W
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.0.1.21' }
  ];
}
else
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');



reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw65031, CSCvw65032',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
