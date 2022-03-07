#TRUSTED 59990ef60a5365df3a71182c1d8eb851d2bb54cb953b995ab782ce16ef5c0c5f98c67f748e83016aedef5a6824021b3f8e818657643bdda8735ed1f0da993e5a126af7ca064b30d393c12807e2dca5b98b1f314f8df62a713c87426eba70aa1693e2e9e941a8eea73c7bf2f7b0859649a09c7d26f17724ef3dad4561401b2f413fe7b89c4eb7add304ebb5420670f2a4b177cfefbb9f1746c963a44549e0b3a7bd111b64245aa39750001038e7f499aa4d16da5d718a89cf05f76967ae1c3a7fe9d6376505d1286c2bd8569d6da8d1d057fab599a357d55823ae9c08fee15324936a0d50eb44c7f30d25ac7431342871fa172b2e10c03fdcb79d79157563476f4509a79258e4178d46b0f28108c49311d946dcf06332e8e19d34b077e509ad778ba90daa095bc75e026fb23252c51e28d22217c731b8e50bb5986d594812ce38b16011088972496615f90e6131797b79474da6ad14fb1b0a7f74ee593a289e21b75f6c9dde74f42fafb6c9e9d51c95253908d760ed9716bc989234336b659e3c4d88f410c77165eee2ea1f43d6962f3d7c6d79ac2c54ca969b864b6ab5012b2fe402a2ffb68aff5383d04089c52138fcb5c9cc42c2d70483ce1c449734dd3e348218eb78faa459b484692e49aa29cc2b45c3daaa9b19048d826e115ed45d3a6e8937e292f2cdb393ff58217d87611ec58f819fcf6a07629ebf4545c0bb791fe2
##
# 
##

include('compat.inc');

if (description)
{
  script_id(148447);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/13");

  script_cve_id("CVE-2021-1137", "CVE-2021-1479", "CVE-2021-1480");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs98509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv87918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw08533");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw31395");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-YuTVWqy");
  script_xref(name:"IAVA", value:"2021-A-0159");

  script_name(english:"Cisco SD-WAN vManage Software Multiple Vulnerabilities (cisco-sa-vmanage-YuTVWqy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage Software installed on the remote host is affected by multiple vulnerabilities as
referenced in the cisco-sa-vmanage-YuTVWqy advisory, as follows:

  - A vulnerability in the remote management component allows an unauthenticated, remote attacker to cause a
    buffer overflow and execute arbitrary code on the underlying operating system with root privileges. This
    is due to improper validation of user-supplied input. An attacker can exploit this by sending a crafted
    connection request. (CVE-2021-1479)

  - A vulnerability in the user management function allows an authenticated, local attacker to gain root
    privileges on the underlying operating system due to insufficient input validation. An attacker can
    exploit this by modifying a user account. (CVE-2021-1137)

  - A vulnerability in the system file transfer functions allows an authenticated, local attacker to gain root
    privileges on the underlying operating system due to improper validation of input to the system file
    transfer functions. An attacker can exploit this by sending crafted requests. (CVE-2021-1480)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-YuTVWqy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be4b5546");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs98509");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv87918");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw08533");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw31395");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs98509, CSCvv87918, CSCvw08533, CSCvw31395");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 250, 269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
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
  {'min_ver' : '0.0', 'fix_ver' : '19.2.4'},
  {'min_ver' : '19.3', 'fix_ver' : '20.3.3'},
  {'min_ver' : '20.4', 'fix_ver' : '20.4.1'}
];

version_list =  make_list(
  '19.2.31',
  '19.2.099',
  '19.2.097'
);
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvs98509, CSCvv87918, CSCvw08533, CSCvw31395',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
