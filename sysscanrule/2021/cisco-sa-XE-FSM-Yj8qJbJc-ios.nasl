#TRUSTED 5ed70fcd6cb876ef7b1c71c5b79bd58bb40a08d85d755bcb1bbbbaaf97afaa8a1065178c3c992bdc9ce651cc9df2576a08e972667963925d3d9db6132cb0ac0bca888694778a8fbb4fdc6dc732905d5ba04271f33b9387e1f4a41ced04072f1fc1f50c1da0507482620d9b55e0f24b63bd07ecb9c30181ca6a181104c1cba86e5abade7dc36fdde272b22e2b99e72954bccae3cc61260a015e97e7d2dc6cb1afa3c7f87b3d45921f217238910147db0c690071a7f5adce811629cb82098bcf2dc67cb1c8a4e3477c9753fd40bd3fde83a098fb505a53093bbac6def9b84ce99c5e0145259b58d8cd435690a911e6b63bec98070a1a3004105c064b31fe2037e7e0cd6797b8166d0fb411a62c192c4f937deb3998dc8cc94c87db30e39ef6161053cab08f881770ade94644b7f750bf3b0956f22c50eb7dcd9227d4a67c204134a1b8ddf881274be6b0b13ce39a5b9c4921753061cbe9eacf871864292e82ce8a6bf274dea43dab9ca76c2728a716b6f6390d79502fb80915ac775340a2a36deddb91d0143c9b4dcfc146e7ea87d0a05539bd6681b9f75a39f52cc68757952a994f957fae4a48536cac1f40b35cdd4066b1e4e1ceb75b4edcf2bb6bb3b765417936fd1da5a5dc65788239d5a54f9932dd473c67c55063b2040f87faf61372196829ee2cbcfc6165b45c45fd8a5cab0d0959b578ea9307201c50b43b05ea5ad5e9
##
# 
##

include('compat.inc');

if (description)
{
  script_id(148217);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1391");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu58308");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-FSM-Yj8qJbJc");

  script_name(english:"Cisco IOS Software Privilege Escalation (cisco-sa-XE-FSM-Yj8qJbJc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by a software privilege escalation
vulnerability. A vulnerability in the dragonite debugger of Cisco IOS XE Software could allow an authenticated, local
attacker to escalate from privilege level 15 to root privilege. The vulnerability is due to the presence of development
testing and verification scripts that remained on the device. An attacker could exploit this vulnerability by bypassing
the consent token mechanism with the residual scripts on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-FSM-Yj8qJbJc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?916c25c7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu58308");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu58308");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(489);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '12.2(6)I1',
  '15.0(2)SE13a',
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.2(4)EA10',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EA',
  '15.2(5)EX',
  '15.2(5a)E',
  '15.2(5a)E1',
  '15.2(5b)E',
  '15.2(5c)E',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7)E2a',
  '15.2(7)E2b',
  '15.2(7)E3',
  '15.2(7)E3k',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.3(3)JF13'
);

reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu58308',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
