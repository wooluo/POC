#TRUSTED 6ee54f8e9492b45b3f5407ce1c75e49b73915b0865836a4bf9f2338d9950cf908f24202d37050235e7eabee2ef4dfd8455723270d003e34570c13c65a10c299a00acfabd129e69ff69120b4bd63d8f6b18c13120560d5dfaa0314bf7df328ae5ef84265994599c139ed0f70f737b34a304a8222815d925e5679b82ea9f54065083c4872f9d95a62ef0d82b3fd58911949c0fb0aa8b6347ddab0ad3e6fb2528d9af55aab061f1cba3a7f1164a281ed5b25ae8dddf018b878fed65d8e529b8a89b6b8dc9bd1a46e7fa9ee920e351abf014a585fb8d83b9daaa79c7973f562930531517da916e693c9b0e7ed80089f3615f5094edc80cc7030ac86cd206e101c3380d349923be0ff5cb1fb03fea9f08b4da6ce56668d3b584f8d901604158af06acd63807cb97e5c5615acb978ff24225c441a12407679c52bc0382e83728d4d75498bdb649d08fd38a9dd820b2ffcd7c812afb575e00395135b596d5e216683b4d6d67e72cab32d462650b76a826df4d9f7795be3ac1ab33fd5f45f1fd0cde5035d5d226fcc4d94fae40ff069ca58cd8ea172c0aaa320b15f40c837f96403c6bf04373348d86740cad0698da2f84aabc4cdc8500475f2e09936614987e175797cd3ec926d6112d741f5bf4275bf8fb2a9e4bb780cb969ba716e03796a5c7c0f3137546f52d667ad109a698573096463129995d13679caf9d54be7c41a76417911f
##
# 
##

include('compat.inc');

if (description)
{
  script_id(148103);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1435");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32553");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-webcmdinjsh-UFJxTgZD");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-iosxe-webcmdinjsh-UFJxTgZD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webcmdinjsh-UFJxTgZD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e57305e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32553");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32553");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1435");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
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
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvq32553',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
