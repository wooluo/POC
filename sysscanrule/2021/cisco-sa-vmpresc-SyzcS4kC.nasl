#TRUSTED 6098b8b6451ec871ffc421f6cb0508ec738f7341962d70190eab4dac2c832b8778d96bc3902a2396abbd87d2213ade90343870a67d17db295f0fb69f9b091d6f410d93bb1169757c031bf1d801724406596966183c08bf6c65896594a29a9590a981d12f80b89caa7812a5a0bce577610279520b16f10e74ce0824039313c04b6235b8d1cd800acd000c408c38ce80fbe5e434ff7607329c67a7ff86dd8f16b54f325330af4d895105dbfe6950a9c7e416c5bcccd471e00002fd551b2763b09a5c674bade57620cf1a92e8070cadcf613f8018da80fc30ee7c96373d3b660d8b613ab743fc88da060b5911806517f52c389dbac9ea8ce59128c14c6b94d008f6e6ffa7da02d19050264d4ad62c40c1e405ea04ba3e034bffb7d0650471f35e55dd85ef4f34ba94c3a88ef6ef192eada60587f8acc74c205f509715ef62fdec26307fad534f16057eb212e508e0802aaab9eb0b66ddd87daee9abea51b372861ecab5305ede672ff402c2bd4ddfc6dfdad473e662063e41b87ee41ec2222858c44d12fcf52b7a9d7236c022e067fde271599d93ef9b78aaba8eb1a9c264e3bb2096f2d97b4a98812393c8986296a45ba87046462d2560c63a3828b26fdae90af7a4a2bf06d19bc16f6bbe76a27304742b878e20da6cd54081cbb73da07e560f148c7cea94dfbb54ac4ebfcd5177f8b960f4048fe26535ab320066655a57391d99
##
# 
##

include('compat.inc');

if (description)
{
  script_id(147876);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/18");

  script_cve_id("CVE-2020-3379");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69987");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmpresc-SyzcS4kC");

  script_name(english:"Cisco SD-WAN Solution Software Privilege Escalation (cisco-sa-vmpresc-SyzcS4kC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution Software is affected by a privilege escalation 
vulnerability due to insufficient input validation. An authenticated, local attacker can exploit this by sending
a crafted request in order to gain administrative privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmpresc-SyzcS4kC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e017be1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69987");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69987");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3379");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/18");

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

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'18.3.0' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69987',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
