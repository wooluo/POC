#TRUSTED 6c62c91fcf776ccc173c68541b035350f7a61a60872516bccb231404913a24518effcb257f0b7ba2cd4bc2d6f3fba47af8e4a66499cccaf4b92bb26b3fc8c5951db400836c175deb466eab0cb888822937d43c299f2c1a3cd7584570af2fbcc3fa6d3282cc963c96f1c71aa4c4548b3c921f215380338d3fabe5c8b2e04634f68fd662b46e1ffb75bddc9a9c1e14a43cde7c6a6cab76f2e775d5aaea557e15364e01cf461fbbf68b02fbcdc7c6fd5c735c3a0797031f2ef38451fbe7167ccf10c22b444e159639a5e41b288e760edd678a1123f9558f083a88544087e1a9f05d5ae29efbf4632d57351baefca3e3fa78d302dc60ee8dd209f7fba55b1ac050d5aaf4f4ce95683450a44dd8dcf84a5dd1299d4bfb36137bb1d0d34cf9396c9944f236308c0d2461eb2be8408325ad72482ffb6858e111a77c6840908c7dad5077f67451623a39f178a74f88a2718633503e760e769dcfddc2b29a4dac6354166d8665d7475fc5c918205322114cbc9c31889c568aaeb84a5f39799ddc6b510dbde3890b3c495d87db2c75240ce1f1f79d1fd1a0f60eebf98e6fd0b8e70ce75812c52ed12d612cac417ebb4aa88c3d469ce03911ba07dacdea3de3172a6d70b26425d505c2f9ce802cc78e6ad18ae98a4ded34a45e8e33ac360f18013a00b423ca32441728ecebc9fac3eb5fd7ce36f9bbed89ff6e906aae79d9824aada4149887
##
# 
##

include('compat.inc');

if (description)
{
  script_id(145422);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/26");

  script_cve_id("CVE-2020-26073");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21754");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-traversal-hQh24tmk");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Directory Traversal (cisco-sa-vman-traversal-hQh24tmk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a directory traversal vulnerability due to
improper validation of directory traversal character sequences within requests to APIs. An unauthenticated, remote
attacker can exploit this, by sending malicious requests to an API within the affected application, to conduct directory
traversal attacks and gain access to sensitive information.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-traversal-hQh24tmk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2bbccbb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21754");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv21754.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26073");

  script_cwe_id(35);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_ver':'0', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.2' }
];

#20.1.12 is not directly referenced in the advisory, but it is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv21754',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);