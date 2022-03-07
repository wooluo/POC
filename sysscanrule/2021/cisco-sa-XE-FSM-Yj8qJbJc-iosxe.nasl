#TRUSTED 30b95232af608f22a59bc5959b7147ffd58bf10c8b9e92ad64a820b6a3ee4e1373f2025e4c4c748cba59522c94e657639dd4df12ab0762c2d63e43406be196209b7441b122a9d0b7f0daebc9dedf04b7ee668f52b19f574415561724620bf0c4a2135ffa315bd0e275cf3ddc1863189e721c6be70f6341774e9da0e7ed3da39f034441456529e593ef66da46593449d0a13d319d71a634afc4e33090800439d118564106cf915892dd34322d2ba576e0df3d9e7238ed365889c29651b4a73a47ae1e75da0a92d46932273f19da3515f62a6f198ebe2827081f9f34ee4d1563ad642b088249c4f1108c87de5e713797049a46a6c1ee201fa47fb23216c585390c3949ebe4d79cb4b944cd032c73b1d44ce8f3720ad0b795ca75e9c1f54a35aa5c531f1a5877a47250a89f46b839cbde9ff9b3f1dcd2f9c9ae4be2b642020e9bd66da65b12f6f3d59f9522eac757d6a81426de539bdfb88f645f3d02ca656f50e6dbf424758de66591980a74513df52abe03b240617fb10561e967a0dc014e361df84a6cfee49d1a9c8f5f67afc881e5764d481c875d87f6e22946bce2a74e79d70d8e1ed4d1017698baa8245bc1f76fd4c2b1bfd41e9645c4206e58eab402d82b028b51f7a4e532ad4f831aec11b3649453c8363518a8abd2e13c206926cfb43d60a8fba0543637a0943b97f7c0e9ca77c49f7ade094baa35ab85b0af23ee0692
##
# 
##

include('compat.inc');

if (description)
{
  script_id(148216);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1391");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu58308");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-FSM-Yj8qJbJc");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-XE-FSM-Yj8qJbJc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a software privilege escalation
vulnerability. The vulnerability is due to the presence of development testing and verification scripts that remained
on the device. An attacker could exploit this vulnerability by bypassing the consent token mechanism with the residual
scripts on the affected device. A successful exploit could allow the attacker to escalate from privilege level 15 to
root privilege.

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3aE',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
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
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3'
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
