#TRUSTED 51708c7dbe16db0d2735343a0077f4d1369f63906ce3e41dac90ef92527bf501cde1f51f4a1882a814960c31263c5a4997ca60b12828957fef5300281341d10568796bb32abe399825ae9b105ae9c734d8c64fba73cec33d6a83bb78b991fe144caab7eb78a7d07f304325aeef92e9502218c84b0b970f67c0b00166b1c6c526824c05cfcd623b3536545719ba832f0a2ccb58cdaadb7ca23219a1f50f8433d7e2541bc0e3ca1089ef27394fe16edf80662f48dd9594fd1d20b2f66a57c2946efbbf9b961262078889a8e970eec054f781d1cae2756f1481dbbab9d9324d212ed3fd67b76eafd9f1da80b1593387838ce66aabfa196472cd73c21ebce6f867cf44f8bda29b14d5bb64199cc367b5a379742ac49e3d25e0685016fe4a5dee42ee26caba6c690eb28e5aee3cdc14e8538ef3e4d5faf0fbabfeb2b32fbd7fc7109bb56ba2a64d5bac40707f077eb2364a24b023429629cb890adee8963ed92d4a37d2e5e7200b5ce0ed3c113c31ba555a2e26c409737511e391f360668ae60c87c062be7024e37d356c0f7886d9fdaf427d35ce0cc7793aded5a360094000111fbb337b4f7006bd7f38325719f0c902cebdbf19ea68929bce1adf06d1448ac4abea138063eb42a51f4b41608b20bdbcd68edaef6774e2eb638774e08122d76f81c8f1965f79052f68d3881b3ff730f860366687d76f1435222e41b4cf7db802e598

##
# 
##



include('compat.inc');

if (description)
{
  script_id(151374);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/07");

  script_cve_id("CVE-2021-1432");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu50633");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-sdwarbcmdexec-sspOMUr3");
  script_xref(name:"IAVA", value:"2021-A-0141");

  script_name(english:"Cisco IOS XE Software SD WAN Arbitrary Command Execution (cisco-sa-iosxe-sdwarbcmdexec-sspOMUr3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the CLI of Cisco IOS XE SD-WAN Software could allow an authenticated, local attacker to execute
arbitrary commands on the underlying operating system as the root user. The attacker must be authenticated on the
affected device as a low-privileged user to exploit this vulnerability. This vulnerability is due to insufficient
validation of user-supplied input. An attacker could exploit this vulnerability by injecting arbitrary commands to
a file as a lower-privileged user. The commands are then executed on the device by the root user. A successful exploit
could allow the attacker to execute arbitrary commands as the root user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-sdwarbcmdexec-sspOMUr3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab9978e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu50633");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu50633");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1432");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Cisco ISR1000, ISR4000, ASR1000, CSR1000V
var model = toupper(product_info['model']);
if(!pgrep(pattern:"ISR[14]0{3}|ASR10{3}|CSR10{3}V", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu50633',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);