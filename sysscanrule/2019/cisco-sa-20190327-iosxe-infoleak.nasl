#TRUSTED 2bb904813385a2f43067a8087e2a829ca28a66418059df5e165513aaf560cd78aa15e00188e10ffb9b1dbf9d7b90b295c128a563aabbf2faf95350b9fc0d86a0f9566b51758bf5fe007e2294354fbb9bb1811fd7a955fc83345064056593379f7865721b59e32d9ecd351c612c38c61ef111b35a43adc90b8d0e6e2abeba7092778aa691fab32528fdaf7373c6a20b37bebb54fba4d7ead6fcfd62233c4009a70fd21df8d441346f6b93d2a521467c31939e4f622b3ce1c07aab4be140af79efb65f32e8c0b4b855ad976a6fb8cf4bc729ffc9175784436c21de522b718db01f03e9b19f53846f3363e44f35c8e6d7f715d21d96681c948a5cdd407aac1b71acbc8b43a08f075e77a621bc0df6b69d6dfd5ac855d649fd41fd50667b2617c065b06bf3131d39542cb7a77945c6897eae915a2faf3b02952bf2722f422459753b8f51f9c30c6c1e632c2d88067ead919bba9051067ae5ac647082f58039a57fc908092172297e7162544e656d3236df47f90170dfac2dbda1bbcefd15e66219952fd3597f1dead91f0b7b77d6aa8bf78f08657c8884a6689b8b6ca4642d86c8f05d096abed46fe59c68ab8b687fe120f155555309e7678a7cb8d382b03dac02b61f12dbdd2569a8cd74f015a750047e254e826badef6814e0de15bddb43d77d375278a631f40a33e7ed3c393efaf11215943991106c8ae514d750064192890557
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126507);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/05 16:05:30");

  script_cve_id("CVE-2019-1761");
  script_xref(name: "CWE", value: "CWE-665");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj98575");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-ios-infoleak");
  script_xref(name:"IAVA", value:"2019-A-0097");

  script_name(english:"Cisco IOS XE Software Hot Standby Router Protocol Information Leak Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Hot Standby Router Protocol
    (HSRP) subsystem of Cisco IOS and IOS XE Software could
    allow an unauthenticated, adjacent attacker to receive
    potentially sensitive information from an affected
    device.The vulnerability is due to insufficient memory
    initialization. An attacker could exploit this
    vulnerability by receiving HSRPv2 traffic from an
    adjacent HSRP member. A successful exploit could allow
    the attacker to receive potentially sensitive
    information from the adjacent device. (CVE-2019-1761)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ios-infoleak
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj98575");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj98575");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1761");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
'16.1.2',
'16.1.3',
'16.2.1',
'16.2.2',
'16.3.1',
'16.3.1a',
'16.3.2',
'16.3.3',
'16.3.4',
'16.3.5',
'16.3.5b',
'16.3.6',
'16.3.7',
'16.4.1',
'16.4.2',
'16.4.3',
'16.5.1',
'16.5.1a',
'16.5.1b',
'16.5.2',
'16.5.3',
'16.6.1',
'16.6.2',
'16.6.3',
'16.6.4',
'16.6.4a',
'16.6.4s',
'16.7.1',
'16.7.1a',
'16.7.1b',
'16.7.2',
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
'16.9.2h',
'16.9.3h',
'3.10.0E',
'3.10.0S',
'3.10.0cE',
'3.10.10S',
'3.10.1E',
'3.10.1S',
'3.10.1aE',
'3.10.1sE',
'3.10.2E',
'3.10.2S',
'3.10.2aS',
'3.10.2tS',
'3.10.3S',
'3.10.4S',
'3.10.5S',
'3.10.6S',
'3.10.7S',
'3.10.8S',
'3.10.8aS',
'3.10.9S',
'3.11.0S',
'3.11.1S',
'3.11.2S',
'3.11.3S',
'3.11.4S',
'3.12.0S',
'3.12.0aS',
'3.12.1S',
'3.12.2S',
'3.12.3S',
'3.12.4S',
'3.13.0S',
'3.13.0aS',
'3.13.10S',
'3.13.1S',
'3.13.2S',
'3.13.2aS',
'3.13.3S',
'3.13.4S',
'3.13.5S',
'3.13.5aS',
'3.13.6S',
'3.13.6aS',
'3.13.6bS',
'3.13.7S',
'3.13.7aS',
'3.13.8S',
'3.13.9S',
'3.14.0S',
'3.14.1S',
'3.14.2S',
'3.14.3S',
'3.14.4S',
'3.15.0S',
'3.15.1S',
'3.15.1cS',
'3.15.2S',
'3.15.3S',
'3.15.4S',
'3.16.0S',
'3.16.0aS',
'3.16.0bS',
'3.16.0cS',
'3.16.1S',
'3.16.1aS',
'3.16.2S',
'3.16.2aS',
'3.16.2bS',
'3.16.3S',
'3.16.3aS',
'3.16.4S',
'3.16.4aS',
'3.16.4bS',
'3.16.4cS',
'3.16.4dS',
'3.16.4eS',
'3.16.4gS',
'3.16.5S',
'3.16.5aS',
'3.16.5bS',
'3.16.6S',
'3.16.6bS',
'3.16.7S',
'3.16.7aS',
'3.16.7bS',
'3.16.8S',
'3.17.0S',
'3.17.1S',
'3.17.1aS',
'3.17.2S',
'3.17.3S',
'3.17.4S',
'3.18.0S',
'3.18.0SP',
'3.18.0aS',
'3.18.1S',
'3.18.1SP',
'3.18.1aSP',
'3.18.1bSP',
'3.18.1cSP',
'3.18.1gSP',
'3.18.1hSP',
'3.18.1iSP',
'3.18.2S',
'3.18.2SP',
'3.18.2aSP',
'3.18.3S',
'3.18.3SP',
'3.18.3aSP',
'3.18.3bSP',
'3.18.4S',
'3.18.4SP',
'3.18.5SP',
'3.2.0SG',
'3.2.10SG',
'3.2.11SG',
'3.2.11aSG',
'3.2.1SG',
'3.2.2SG',
'3.2.3SG',
'3.2.4SG',
'3.2.5SG',
'3.2.6SG',
'3.2.7SG',
'3.2.8SG',
'3.2.9SG',
'3.3.0SE',
'3.3.0SG',
'3.3.0SQ',
'3.3.0XO',
'3.3.1SE',
'3.3.1SG',
'3.3.1SQ',
'3.3.1XO',
'3.3.2SE',
'3.3.2SG',
'3.3.2XO',
'3.3.3SE',
'3.3.4SE',
'3.3.5SE',
'3.4.0SG',
'3.4.0SQ',
'3.4.1SG',
'3.4.1SQ',
'3.4.2SG',
'3.4.3SG',
'3.4.4SG',
'3.4.5SG',
'3.4.6SG',
'3.4.7SG',
'3.4.8SG',
'3.5.0E',
'3.5.0SQ',
'3.5.1E',
'3.5.1SQ',
'3.5.2E',
'3.5.2SQ',
'3.5.3E',
'3.5.3SQ',
'3.5.4SQ',
'3.5.5SQ',
'3.5.6SQ',
'3.5.7SQ',
'3.5.8SQ',
'3.6.0E',
'3.6.0aE',
'3.6.0bE',
'3.6.1E',
'3.6.2E',
'3.6.2aE',
'3.6.3E',
'3.6.4E',
'3.6.5E',
'3.6.5aE',
'3.6.5bE',
'3.6.6E',
'3.6.7E',
'3.6.7aE',
'3.6.7bE',
'3.6.8E',
'3.6.9E',
'3.6.9aE',
'3.7.0E',
'3.7.0S',
'3.7.0bS',
'3.7.1E',
'3.7.1S',
'3.7.1aS',
'3.7.2E',
'3.7.2S',
'3.7.2tS',
'3.7.3E',
'3.7.3S',
'3.7.4E',
'3.7.4S',
'3.7.4aS',
'3.7.5E',
'3.7.5S',
'3.7.6S',
'3.7.7S',
'3.7.8S',
'3.8.0E',
'3.8.0S',
'3.8.1E',
'3.8.1S',
'3.8.2E',
'3.8.2S',
'3.8.3E',
'3.8.4E',
'3.8.5E',
'3.8.5aE',
'3.8.6E',
'3.8.7E',
'3.9.0E',
'3.9.0S',
'3.9.0aS',
'3.9.1E',
'3.9.1S',
'3.9.1aS',
'3.9.2E',
'3.9.2S',
'3.9.2bE'
);

workarounds = make_list(CISCO_WORKAROUNDS['hsrp_v2']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , make_list('CSCvj98575'),
  'cmds'     , make_list('show standby')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
