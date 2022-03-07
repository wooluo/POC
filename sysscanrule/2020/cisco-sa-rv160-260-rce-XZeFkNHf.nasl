#TRUSTED 0ae2540d7a868919d45a6e5a52ed0fb9834adf49db795f65407456dd5d15a5c49d1e64e091f637eb97c37f55314038a2e62d3fcbf014e56b1fc8bcd37b2b390c2d89f4609b22b047ada471d6afc4ff5762d2a10eae3c704f0e100eb7eb79432b8b46aad40d74c4463f8302f3474778ddcd513c05904c89375292880224c9a789f49cefdb43ab5095817b227aa345ce7325084c78ce97f287bbeb2fab100434e418a4930332b0c15e1df9ee61b3f0aa373121a71bfa0c49da66cbd2961866fcbb16de400e3d0c1c3299fe874f60ff4cb9d34f48c5506eb37b1401d7521bb0c764de0478423d209b5969404b54776dd72383f7f96d45bf3cd2f341a58492c4322cd3bae7abf7cf6f96a89b457e11704c6519cea01c48b779983b4114df5186b697907d5d47c664b46029534c6f74b64d365bd32d022d2c6a5caf0cf4761925347d39ab3821195f39bc610d56f0cc10e58a7575e336501cabef4a418ee9a63a1abe9f27f4a929630f47c974d8b3cc4ef38c5248a16249036e33fb5742fd7f0c78c57d97c900715eec3a21b21bbdee5cd233251d0c64b495d137157a00e75eed660fe761e290edf5784ea17e05994a4ff84f8b800114ebe048268f348615c7cbf9869b5da3f4db4949d87e0a1665e9cb5486e4c2c863e1e50b11f8c4e3229f59653f808c1439a0cc7cc5c2993a2e343c664d4d34db6e9eb2b3f9b18b7ff5b44be817
##
# 
##

include('compat.inc');

if (description)
{
  script_id(146268);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id(
    "CVE-2021-1289",
    "CVE-2021-1290",
    "CVE-2021-1291",
    "CVE-2021-1292",
    "CVE-2021-1293",
    "CVE-2021-1294",
    "CVE-2021-1295"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw13908");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw13917");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19718");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw27923");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw27982");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw50568");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv160-260-rce-XZeFkNHf");
  script_xref(name:"IAVA", value:"2021-A-0063");

  script_name(english:"Cisco Small Business RV Series VPN Multiple RCE (cisco-sa-rv160-260-rce-XZeFkNHf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
remote code execution (RCE) vulnerabilities in the web-based management interface due to improper validation of HTTP
requests. An unauthenticated, remote attacker could exploit this by sending a crafted HTTP request to the web-based
management to execute arbitrary code as the root user on an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv160-260-rce-XZeFkNHf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ad3e5a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw13908");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw13917");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19718");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19849");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw27923");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw27982");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw50568");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw13908, CSCvw13917, CSCvw19718, CSCvw19849,
CSCvw27923, CSCvw27982, CSCvw50568");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(472);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (product_info.model !~ "^RV(160|260)($|[^0-9])") # RV160 / RV160W / RV260 / RV260W / RV260P
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '1.0.01.02' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw13908, CSCvw13917, CSCvw19718, CSCvw19849, CSCvw27923, CSCvw27982, CSCvw50568',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
