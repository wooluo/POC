#TRUSTED 1c3d4395820957be275f3888acf623a43c748fbfc96f5f58359f5104d5fc5a8dac94ee09e80c77d1fdbbffeca2c7f8906212984bbcef38e8637913d534062b9b15e5cf55a9d64813d60b265e542bee0b756b1321d1a150999e52661fcaf3eee5d6e4bf2e9a34653e86ecb6745e0111b8e31292edf8a2fc9efba4dc5d01f5db2a57541bac28b526a5dc9e5fcb5f19ca9f8f896dcc59574faa5713b51d23f8024ad3e53e4ba8d693a939cacae03007a384bec699fd515529893009417b4b1fc09f4b32e549e0a22f0b3c6c1d8bca3334b7b998b4c5254a09ccaa0c24b4d8254fe5eb5c43251c4584021bbecc7e771793265c1df276b0acaa1e4aad1312df2e8e3fc143b8eb7af0ec0d9377a15afb6c86028108aefaea769d63e7438c0f3878c5df062e24b8a41dd73ae7e51b69d2ac5b3ff3b351aee36bddc562a4158a98c814f5cd431021c90bafdf49c1181dab0adc48f47f73089ceedf659069695e0772147863f399c7b842e97aab1341c8dae6ae888f54401ba786b1d1ae8cf68d1422e767c09c9f35a5333db93076596c8b6c667a7faa0f7e87ffb535b76cb27b8a0e53232b310b8cc4a2c3da1753792239a28051c3ab15798b03b72396f229a0e2ad055eb1509c45bd57ba69182143d64fffaba7acf5ab296b7329bed00ffb6964c43c6704202acd83486105224590e2b1044e0b286fa35a5e59b78d22fe3ffb4f5aeb9e
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123792);
  script_version("1.6");
  script_cvs_date("Date: 2019/08/19  8:27:14");

  script_cve_id("CVE-2019-1761");
  script_xref(name: "CWE", value: "CWE-665");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj98575");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-ios-infoleak");
  script_xref(name:"IAVA", value:"2019-A-0097");

  script_name(english:"Cisco IOS Software Hot Standby Router Protocol Information Leak Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '12.2(33)CX',
  '12.2(33)CY',
  '12.2(33)CY1',
  '12.2(33)CY2',
  '12.2(33)IRA',
  '12.2(33)IRB',
  '12.2(33)IRC',
  '12.2(33)IRD',
  '12.2(33)IRE',
  '12.2(33)IRE1',
  '12.2(33)IRE2',
  '12.2(33)IRF',
  '12.2(33)IRG',
  '12.2(33)IRG1',
  '12.2(33)IRH',
  '12.2(33)IRH1',
  '12.2(33)MRA',
  '12.2(33)MRB',
  '12.2(33)MRB1',
  '12.2(33)MRB2',
  '12.2(33)MRB3',
  '12.2(33)MRB4',
  '12.2(33)MRB5',
  '12.2(33)MRB6',
  '12.2(33)SB',
  '12.2(33)SB1',
  '12.2(33)SB10',
  '12.2(33)SB11',
  '12.2(33)SB12',
  '12.2(33)SB13',
  '12.2(33)SB14',
  '12.2(33)SB15',
  '12.2(33)SB16',
  '12.2(33)SB17',
  '12.2(33)SB1a',
  '12.2(33)SB1b',
  '12.2(33)SB2',
  '12.2(33)SB3',
  '12.2(33)SB4',
  '12.2(33)SB5',
  '12.2(33)SB6',
  '12.2(33)SB6a',
  '12.2(33)SB6b',
  '12.2(33)SB7',
  '12.2(33)SB8',
  '12.2(33)SB8a',
  '12.2(33)SB8b',
  '12.2(33)SB8c',
  '12.2(33)SB8d',
  '12.2(33)SB8e',
  '12.2(33)SB8f',
  '12.2(33)SB8g',
  '12.2(33)SB9',
  '12.2(33)SCA',
  '12.2(33)SCA1',
  '12.2(33)SCA2',
  '12.2(33)SCB',
  '12.2(33)SCB1',
  '12.2(33)SCB10',
  '12.2(33)SCB11',
  '12.2(33)SCB2',
  '12.2(33)SCB3',
  '12.2(33)SCB4',
  '12.2(33)SCB5',
  '12.2(33)SCB6',
  '12.2(33)SCB7',
  '12.2(33)SCB8',
  '12.2(33)SCB9',
  '12.2(33)SCC',
  '12.2(33)SCC1',
  '12.2(33)SCC2',
  '12.2(33)SCC3',
  '12.2(33)SCC4',
  '12.2(33)SCC5',
  '12.2(33)SCC6',
  '12.2(33)SCC7',
  '12.2(33)SCD',
  '12.2(33)SCD1',
  '12.2(33)SCD2',
  '12.2(33)SCD3',
  '12.2(33)SCD4',
  '12.2(33)SCD5',
  '12.2(33)SCD6',
  '12.2(33)SCD7',
  '12.2(33)SCD8',
  '12.2(33)SCE',
  '12.2(33)SCE1',
  '12.2(33)SCE2',
  '12.2(33)SCE3',
  '12.2(33)SCE4',
  '12.2(33)SCE5',
  '12.2(33)SCE6',
  '12.2(33)SCF',
  '12.2(33)SCF1',
  '12.2(33)SCF2',
  '12.2(33)SCF3',
  '12.2(33)SCF4',
  '12.2(33)SCF5',
  '12.2(33)SCG',
  '12.2(33)SCG1',
  '12.2(33)SCG2',
  '12.2(33)SCG3',
  '12.2(33)SCG4',
  '12.2(33)SCG5',
  '12.2(33)SCG6',
  '12.2(33)SCG7',
  '12.2(33)SCH',
  '12.2(33)SCH0a',
  '12.2(33)SCH1',
  '12.2(33)SCH2',
  '12.2(33)SCH2a',
  '12.2(33)SCH3',
  '12.2(33)SCH4',
  '12.2(33)SCH5',
  '12.2(33)SCH6',
  '12.2(33)SCI',
  '12.2(33)SCI1',
  '12.2(33)SCI1a',
  '12.2(33)SCI2',
  '12.2(33)SCI2a',
  '12.2(33)SCI3',
  '12.2(33)SCJ',
  '12.2(33)SCJ1a',
  '12.2(33)SCJ2',
  '12.2(33)SCJ2a',
  '12.2(33)SCJ2b',
  '12.2(33)SCJ2c',
  '12.2(33)SCJ3',
  '12.2(33)SCJ4',
  '12.2(33)SRB',
  '12.2(33)SRB1',
  '12.2(33)SRB2',
  '12.2(33)SRB3',
  '12.2(33)SRB4',
  '12.2(33)SRB5',
  '12.2(33)SRB5a',
  '12.2(33)SRB6',
  '12.2(33)SRB7',
  '12.2(33)SRC',
  '12.2(33)SRC1',
  '12.2(33)SRC2',
  '12.2(33)SRC3',
  '12.2(33)SRC4',
  '12.2(33)SRC5',
  '12.2(33)SRC6',
  '12.2(33)SRD',
  '12.2(33)SRD1',
  '12.2(33)SRD2',
  '12.2(33)SRD2a',
  '12.2(33)SRD3',
  '12.2(33)SRD4',
  '12.2(33)SRD4a',
  '12.2(33)SRD5',
  '12.2(33)SRD6',
  '12.2(33)SRD7',
  '12.2(33)SRD8',
  '12.2(33)SRE',
  '12.2(33)SRE0a',
  '12.2(33)SRE1',
  '12.2(33)SRE10',
  '12.2(33)SRE11',
  '12.2(33)SRE12',
  '12.2(33)SRE13',
  '12.2(33)SRE14',
  '12.2(33)SRE15',
  '12.2(33)SRE15a',
  '12.2(33)SRE2',
  '12.2(33)SRE3',
  '12.2(33)SRE4',
  '12.2(33)SRE5',
  '12.2(33)SRE6',
  '12.2(33)SRE7',
  '12.2(33)SRE7a',
  '12.2(33)SRE8',
  '12.2(33)SRE9',
  '12.2(33)SRE9a',
  '12.2(33)STE0',
  '12.2(33)SXI',
  '12.2(33)SXI1',
  '12.2(33)SXI10',
  '12.2(33)SXI11',
  '12.2(33)SXI12',
  '12.2(33)SXI13',
  '12.2(33)SXI14',
  '12.2(33)SXI2',
  '12.2(33)SXI2a',
  '12.2(33)SXI3',
  '12.2(33)SXI3a',
  '12.2(33)SXI3z',
  '12.2(33)SXI4',
  '12.2(33)SXI4a',
  '12.2(33)SXI5',
  '12.2(33)SXI5a',
  '12.2(33)SXI6',
  '12.2(33)SXI7',
  '12.2(33)SXI8',
  '12.2(33)SXI8a',
  '12.2(33)SXI9',
  '12.2(33)SXI9a',
  '12.2(33)SXJ',
  '12.2(33)SXJ1',
  '12.2(33)SXJ10',
  '12.2(33)SXJ2',
  '12.2(33)SXJ3',
  '12.2(33)SXJ4',
  '12.2(33)SXJ5',
  '12.2(33)SXJ6',
  '12.2(33)SXJ7',
  '12.2(33)SXJ8',
  '12.2(33)SXJ9',
  '12.2(33)ZI',
  '12.2(33)ZZ',
  '12.2(34)SB1',
  '12.2(34)SB2',
  '12.2(34)SB3',
  '12.2(34)SB4',
  '12.2(34)SB4a',
  '12.2(34)SB4b',
  '12.2(34)SB4c',
  '12.2(34)SB4d',
  '12.2(46)SE',
  '12.2(46)SG',
  '12.2(46)SG1',
  '12.2(50)SE',
  '12.2(50)SE1',
  '12.2(50)SE2',
  '12.2(50)SE3',
  '12.2(50)SE4',
  '12.2(50)SE5',
  '12.2(50)SG',
  '12.2(50)SG1',
  '12.2(50)SG2',
  '12.2(50)SG3',
  '12.2(50)SG4',
  '12.2(50)SG5',
  '12.2(50)SG6',
  '12.2(50)SG7',
  '12.2(50)SG8',
  '12.2(50)SQ',
  '12.2(50)SQ1',
  '12.2(50)SQ2',
  '12.2(50)SQ3',
  '12.2(50)SQ4',
  '12.2(50)SQ5',
  '12.2(50)SQ6',
  '12.2(50)SQ7',
  '12.2(52)EX',
  '12.2(52)EX1',
  '12.2(52)EY',
  '12.2(52)EY1',
  '12.2(52)EY1a',
  '12.2(52)EY1b',
  '12.2(52)EY1c',
  '12.2(52)EY2',
  '12.2(52)EY2a',
  '12.2(52)EY3',
  '12.2(52)EY3a',
  '12.2(52)EY4',
  '12.2(52)SE',
  '12.2(52)SE1',
  '12.2(52)SG',
  '12.2(52)XO',
  '12.2(53)EX',
  '12.2(53)EY',
  '12.2(53)SE',
  '12.2(53)SE1',
  '12.2(53)SE2',
  '12.2(53)SG1',
  '12.2(53)SG10',
  '12.2(53)SG11',
  '12.2(53)SG2',
  '12.2(53)SG3',
  '12.2(53)SG4',
  '12.2(53)SG5',
  '12.2(53)SG6',
  '12.2(53)SG7',
  '12.2(53)SG8',
  '12.2(53)SG9',
  '12.2(54)SE',
  '12.2(54)SG',
  '12.2(54)SG1',
  '12.2(54)WO',
  '12.2(54)XO',
  '12.2(55)EX',
  '12.2(55)EX1',
  '12.2(55)EX2',
  '12.2(55)EX3',
  '12.2(55)EY',
  '12.2(55)EZ',
  '12.2(55)SE',
  '12.2(55)SE1',
  '12.2(55)SE10',
  '12.2(55)SE11',
  '12.2(55)SE12',
  '12.2(55)SE13',
  '12.2(55)SE2',
  '12.2(55)SE3',
  '12.2(55)SE4',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '12.2(55)SE7',
  '12.2(55)SE8',
  '12.2(55)SE9',
  '12.2(58)EX',
  '12.2(58)EY',
  '12.2(58)EY1',
  '12.2(58)EY2',
  '12.2(58)EZ',
  '12.2(58)SE',
  '12.2(58)SE1',
  '12.2(58)SE2',
  '12.2(6)I1',
  '12.2(60)EZ',
  '12.2(60)EZ1',
  '12.2(60)EZ10',
  '12.2(60)EZ11',
  '12.2(60)EZ12',
  '12.2(60)EZ13',
  '12.2(60)EZ14',
  '12.2(60)EZ2',
  '12.2(60)EZ3',
  '12.2(60)EZ4',
  '12.2(60)EZ5',
  '12.2(60)EZ6',
  '12.2(60)EZ7',
  '12.2(60)EZ8',
  '12.2(60)EZ9',
  '12.4(11)MD',
  '12.4(11)MD1',
  '12.4(11)MD10',
  '12.4(11)MD2',
  '12.4(11)MD3',
  '12.4(11)MD4',
  '12.4(11)MD5',
  '12.4(11)MD6',
  '12.4(11)MD7',
  '12.4(11)MD8',
  '12.4(11)MD9',
  '12.4(11)MR',
  '12.4(11)SW',
  '12.4(11)SW1',
  '12.4(11)SW2',
  '12.4(11)SW3',
  '12.4(11)T',
  '12.4(11)T1',
  '12.4(11)T2',
  '12.4(11)T3',
  '12.4(11)T4',
  '12.4(11)XJ',
  '12.4(11)XJ1',
  '12.4(11)XJ2',
  '12.4(11)XJ3',
  '12.4(11)XJ4',
  '12.4(11)XJ5',
  '12.4(11)XJ6',
  '12.4(11)XV',
  '12.4(11)XV1',
  '12.4(11)XW',
  '12.4(11)XW1',
  '12.4(11)XW10',
  '12.4(11)XW2',
  '12.4(11)XW3',
  '12.4(11)XW4',
  '12.4(11)XW5',
  '12.4(11)XW6',
  '12.4(11)XW7',
  '12.4(11)XW8',
  '12.4(11)XW9',
  '12.4(12)MR',
  '12.4(12)MR1',
  '12.4(12)MR2',
  '12.4(14)XK',
  '12.4(15)MD',
  '12.4(15)MD1',
  '12.4(15)MD1a',
  '12.4(15)MD2',
  '12.4(15)MD3',
  '12.4(15)MD4',
  '12.4(15)MD5',
  '12.4(15)SW',
  '12.4(15)SW1',
  '12.4(15)SW2',
  '12.4(15)SW3',
  '12.4(15)SW4',
  '12.4(15)SW5',
  '12.4(15)SW6',
  '12.4(15)SW7',
  '12.4(15)SW8',
  '12.4(15)SW8a',
  '12.4(15)SW9',
  '12.4(15)T',
  '12.4(15)T1',
  '12.4(15)T10',
  '12.4(15)T11',
  '12.4(15)T12',
  '12.4(15)T13',
  '12.4(15)T13b',
  '12.4(15)T14',
  '12.4(15)T15',
  '12.4(15)T16',
  '12.4(15)T17',
  '12.4(15)T2',
  '12.4(15)T3',
  '12.4(15)T4',
  '12.4(15)T5',
  '12.4(15)T6',
  '12.4(15)T6a',
  '12.4(15)T7',
  '12.4(15)T8',
  '12.4(15)T9',
  '12.4(15)XF',
  '12.4(15)XL',
  '12.4(15)XL1',
  '12.4(15)XL2',
  '12.4(15)XL3',
  '12.4(15)XL4',
  '12.4(15)XL5',
  '12.4(15)XM',
  '12.4(15)XM1',
  '12.4(15)XM2',
  '12.4(15)XM3',
  '12.4(15)XN',
  '12.4(15)XQ',
  '12.4(15)XQ1',
  '12.4(15)XQ2',
  '12.4(15)XQ2a',
  '12.4(15)XQ2b',
  '12.4(15)XQ2c',
  '12.4(15)XQ2d',
  '12.4(15)XQ3',
  '12.4(15)XQ4',
  '12.4(15)XQ5',
  '12.4(15)XQ6',
  '12.4(15)XQ7',
  '12.4(15)XQ8',
  '12.4(15)XR',
  '12.4(15)XR1',
  '12.4(15)XR10',
  '12.4(15)XR2',
  '12.4(15)XR3',
  '12.4(15)XR4',
  '12.4(15)XR5',
  '12.4(15)XR6',
  '12.4(15)XR7',
  '12.4(15)XR8',
  '12.4(15)XR9',
  '12.4(15)XY',
  '12.4(15)XY1',
  '12.4(15)XY2',
  '12.4(15)XY3',
  '12.4(15)XY4',
  '12.4(15)XY5',
  '12.4(15)XZ',
  '12.4(15)XZ1',
  '12.4(15)XZ2',
  '12.4(16)MR',
  '12.4(16)MR1',
  '12.4(16)MR2',
  '12.4(19)MR',
  '12.4(19)MR1',
  '12.4(19)MR2',
  '12.4(19)MR3',
  '12.4(2)XA',
  '12.4(2)XA1',
  '12.4(2)XA2',
  '12.4(20)MR',
  '12.4(20)MR1',
  '12.4(20)MR2',
  '12.4(20)MRB',
  '12.4(20)MRB1',
  '12.4(20)T',
  '12.4(20)T1',
  '12.4(20)T2',
  '12.4(20)T3',
  '12.4(20)T4',
  '12.4(20)T5',
  '12.4(20)T5a',
  '12.4(20)T6',
  '12.4(20)T9',
  '12.4(22)MD',
  '12.4(22)MD1',
  '12.4(22)MD2',
  '12.4(22)MDA',
  '12.4(22)MDA1',
  '12.4(22)MDA2',
  '12.4(22)MDA3',
  '12.4(22)MDA4',
  '12.4(22)MDA5',
  '12.4(22)MDA6',
  '12.4(22)T',
  '12.4(22)T1',
  '12.4(22)T2',
  '12.4(22)T3',
  '12.4(22)T4',
  '12.4(22)T5',
  '12.4(22)XR1',
  '12.4(22)XR10',
  '12.4(22)XR11',
  '12.4(22)XR12',
  '12.4(22)XR2',
  '12.4(22)XR3',
  '12.4(22)XR4',
  '12.4(22)XR5',
  '12.4(22)XR6',
  '12.4(22)XR7',
  '12.4(22)XR8',
  '12.4(22)XR9',
  '12.4(24)MD',
  '12.4(24)MD1',
  '12.4(24)MD2',
  '12.4(24)MD3',
  '12.4(24)MD4',
  '12.4(24)MD5',
  '12.4(24)MD6',
  '12.4(24)MD7',
  '12.4(24)MDA',
  '12.4(24)MDA1',
  '12.4(24)MDA10',
  '12.4(24)MDA11',
  '12.4(24)MDA12',
  '12.4(24)MDA13',
  '12.4(24)MDA2',
  '12.4(24)MDA3',
  '12.4(24)MDA4',
  '12.4(24)MDA5',
  '12.4(24)MDA6',
  '12.4(24)MDA7',
  '12.4(24)MDA8',
  '12.4(24)MDA9',
  '12.4(24)MDB',
  '12.4(24)MDB1',
  '12.4(24)MDB10',
  '12.4(24)MDB11',
  '12.4(24)MDB12',
  '12.4(24)MDB13',
  '12.4(24)MDB14',
  '12.4(24)MDB15',
  '12.4(24)MDB16',
  '12.4(24)MDB17',
  '12.4(24)MDB18',
  '12.4(24)MDB19',
  '12.4(24)MDB3',
  '12.4(24)MDB4',
  '12.4(24)MDB5',
  '12.4(24)MDB5a',
  '12.4(24)MDB6',
  '12.4(24)MDB7',
  '12.4(24)MDB8',
  '12.4(24)MDB9',
  '12.4(24)T',
  '12.4(24)T1',
  '12.4(24)T10',
  '12.4(24)T11',
  '12.4(24)T12',
  '12.4(24)T2',
  '12.4(24)T3',
  '12.4(24)T3e',
  '12.4(24)T3f',
  '12.4(24)T4',
  '12.4(24)T4a',
  '12.4(24)T4b',
  '12.4(24)T4c',
  '12.4(24)T4d',
  '12.4(24)T4e',
  '12.4(24)T4f',
  '12.4(24)T4g',
  '12.4(24)T4h',
  '12.4(24)T4i',
  '12.4(24)T4j',
  '12.4(24)T4k',
  '12.4(24)T4l',
  '12.4(24)T4m',
  '12.4(24)T4n',
  '12.4(24)T4o',
  '12.4(24)T5',
  '12.4(24)T6',
  '12.4(24)T7',
  '12.4(24)T8',
  '12.4(24)T9',
  '12.4(24)YG',
  '12.4(24)YG1',
  '12.4(24)YG2',
  '12.4(24)YG3',
  '12.4(24)YG4',
  '12.4(24)YS',
  '12.4(24)YS1',
  '12.4(24)YS10',
  '12.4(24)YS2',
  '12.4(24)YS3',
  '12.4(24)YS4',
  '12.4(24)YS5',
  '12.4(24)YS6',
  '12.4(24)YS7',
  '12.4(24)YS8',
  '12.4(24)YS8a',
  '12.4(24)YS9',
  '12.4(4)MR',
  '12.4(4)MR1',
  '12.4(4)T',
  '12.4(4)T1',
  '12.4(4)T2',
  '12.4(4)T3',
  '12.4(4)T4',
  '12.4(4)T5',
  '12.4(4)T6',
  '12.4(4)T7',
  '12.4(4)T8',
  '12.4(4)XC',
  '12.4(4)XC1',
  '12.4(4)XC2',
  '12.4(4)XC3',
  '12.4(4)XC4',
  '12.4(4)XC5',
  '12.4(4)XC6',
  '12.4(4)XC7',
  '12.4(4)XD',
  '12.4(4)XD1',
  '12.4(4)XD10',
  '12.4(4)XD11',
  '12.4(4)XD12',
  '12.4(4)XD2',
  '12.4(4)XD3',
  '12.4(4)XD4',
  '12.4(4)XD5',
  '12.4(4)XD6',
  '12.4(4)XD7',
  '12.4(4)XD8',
  '12.4(4)XD9',
  '12.4(6)MR',
  '12.4(6)MR1',
  '12.4(6)T',
  '12.4(6)T1',
  '12.4(6)T10',
  '12.4(6)T11',
  '12.4(6)T12',
  '12.4(6)T2',
  '12.4(6)T3',
  '12.4(6)T4',
  '12.4(6)T5',
  '12.4(6)T5a',
  '12.4(6)T5b',
  '12.4(6)T5c',
  '12.4(6)T5d',
  '12.4(6)T5e',
  '12.4(6)T5f',
  '12.4(6)T6',
  '12.4(6)T7',
  '12.4(6)T8',
  '12.4(6)T9',
  '12.4(6)XE',
  '12.4(6)XE1',
  '12.4(6)XE2',
  '12.4(6)XP',
  '12.4(6)XT',
  '12.4(6)XT1',
  '12.4(6)XT2',
  '12.4(9)MR',
  '12.4(9)T',
  '12.4(9)T0a',
  '12.4(9)T1',
  '12.4(9)T2',
  '12.4(9)T3',
  '12.4(9)T4',
  '12.4(9)T5',
  '12.4(9)T6',
  '12.4(9)T7',
  '12.4(9)XG',
  '12.4(9)XG1',
  '12.4(9)XG2',
  '12.4(9)XG3',
  '12.4(9)XG4',
  '12.4(9)XG5',
  '15.0(1)EX',
  '15.0(1)EY',
  '15.0(1)EY2',
  '15.0(1)M',
  '15.0(1)M1',
  '15.0(1)M10',
  '15.0(1)M2',
  '15.0(1)M3',
  '15.0(1)M4',
  '15.0(1)M5',
  '15.0(1)M6',
  '15.0(1)M6a',
  '15.0(1)M7',
  '15.0(1)M8',
  '15.0(1)M9',
  '15.0(1)MR',
  '15.0(1)S',
  '15.0(1)S1',
  '15.0(1)S2',
  '15.0(1)S3a',
  '15.0(1)S4',
  '15.0(1)S4a',
  '15.0(1)S5',
  '15.0(1)S6',
  '15.0(1)SE',
  '15.0(1)SE1',
  '15.0(1)SE2',
  '15.0(1)SE3',
  '15.0(1)SY',
  '15.0(1)SY1',
  '15.0(1)SY10',
  '15.0(1)SY2',
  '15.0(1)SY3',
  '15.0(1)SY4',
  '15.0(1)SY5',
  '15.0(1)SY6',
  '15.0(1)SY7',
  '15.0(1)SY7a',
  '15.0(1)SY8',
  '15.0(1)SY9',
  '15.0(1)XA',
  '15.0(1)XA1',
  '15.0(1)XA2',
  '15.0(1)XA3',
  '15.0(1)XA4',
  '15.0(1)XA5',
  '15.0(1)XO',
  '15.0(1)XO1',
  '15.0(2)EJ',
  '15.0(2)EJ1',
  '15.0(2)EK',
  '15.0(2)EK1',
  '15.0(2)EX',
  '15.0(2)EX1',
  '15.0(2)EX10',
  '15.0(2)EX11',
  '15.0(2)EX12',
  '15.0(2)EX13',
  '15.0(2)EX2',
  '15.0(2)EX3',
  '15.0(2)EX4',
  '15.0(2)EX5',
  '15.0(2)EX6',
  '15.0(2)EX7',
  '15.0(2)EX8',
  '15.0(2)EY',
  '15.0(2)EY1',
  '15.0(2)EY2',
  '15.0(2)EY3',
  '15.0(2)EZ',
  '15.0(2)MR',
  '15.0(2)SE',
  '15.0(2)SE1',
  '15.0(2)SE10',
  '15.0(2)SE10a',
  '15.0(2)SE11',
  '15.0(2)SE12',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.0(2)SG',
  '15.0(2)SG1',
  '15.0(2)SG10',
  '15.0(2)SG11',
  '15.0(2)SG11a',
  '15.0(2)SG2',
  '15.0(2)SG3',
  '15.0(2)SG4',
  '15.0(2)SG5',
  '15.0(2)SG6',
  '15.0(2)SG7',
  '15.0(2)SG8',
  '15.0(2)SG9',
  '15.0(2)SQD',
  '15.0(2)SQD1',
  '15.0(2)SQD2',
  '15.0(2)SQD3',
  '15.0(2)SQD4',
  '15.0(2)SQD5',
  '15.0(2)SQD6',
  '15.0(2)SQD7',
  '15.0(2)SQD8',
  '15.0(2)XO',
  '15.0(2a)EX5',
  '15.0(2a)SE9',
  '15.1(1)S',
  '15.1(1)S1',
  '15.1(1)S2',
  '15.1(1)SG',
  '15.1(1)SG1',
  '15.1(1)SG2',
  '15.1(1)SY',
  '15.1(1)SY1',
  '15.1(1)SY2',
  '15.1(1)SY3',
  '15.1(1)SY4',
  '15.1(1)SY5',
  '15.1(1)SY6',
  '15.1(1)T',
  '15.1(1)T1',
  '15.1(1)T2',
  '15.1(1)T3',
  '15.1(1)T4',
  '15.1(1)T5',
  '15.1(1)XB',
  '15.1(1)XB1',
  '15.1(1)XB2',
  '15.1(1)XB3',
  '15.1(2)GC',
  '15.1(2)GC1',
  '15.1(2)GC2',
  '15.1(2)S',
  '15.1(2)S1',
  '15.1(2)S2',
  '15.1(2)SG',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.1(2)SG8',
  '15.1(2)SG8a',
  '15.1(2)SY',
  '15.1(2)SY1',
  '15.1(2)SY10',
  '15.1(2)SY11',
  '15.1(2)SY12',
  '15.1(2)SY13',
  '15.1(2)SY2',
  '15.1(2)SY3',
  '15.1(2)SY4',
  '15.1(2)SY4a',
  '15.1(2)SY5',
  '15.1(2)SY6',
  '15.1(2)SY7',
  '15.1(2)SY8',
  '15.1(2)SY9',
  '15.1(2)T',
  '15.1(2)T0a',
  '15.1(2)T1',
  '15.1(2)T2',
  '15.1(2)T2a',
  '15.1(2)T3',
  '15.1(2)T4',
  '15.1(2)T5',
  '15.1(3)MRA',
  '15.1(3)MRA1',
  '15.1(3)MRA2',
  '15.1(3)MRA3',
  '15.1(3)MRA4',
  '15.1(3)S',
  '15.1(3)S0a',
  '15.1(3)S1',
  '15.1(3)S2',
  '15.1(3)S3',
  '15.1(3)S4',
  '15.1(3)S5',
  '15.1(3)S5a',
  '15.1(3)S6',
  '15.1(3)S7',
  '15.1(3)SVK4b',
  '15.1(3)T',
  '15.1(3)T1',
  '15.1(3)T2',
  '15.1(3)T3',
  '15.1(3)T4',
  '15.1(4)GC',
  '15.1(4)GC1',
  '15.1(4)GC2',
  '15.1(4)M',
  '15.1(4)M0a',
  '15.1(4)M0b',
  '15.1(4)M1',
  '15.1(4)M10',
  '15.1(4)M12a',
  '15.1(4)M12c',
  '15.1(4)M2',
  '15.1(4)M3',
  '15.1(4)M3a',
  '15.1(4)M4',
  '15.1(4)M5',
  '15.1(4)M6',
  '15.1(4)M7',
  '15.1(4)M8',
  '15.1(4)M9',
  '15.1(4)XB4',
  '15.1(4)XB5',
  '15.1(4)XB5a',
  '15.1(4)XB6',
  '15.1(4)XB7',
  '15.1(4)XB8',
  '15.1(4)XB8a',
  '15.2(1)E',
  '15.2(1)E1',
  '15.2(1)E2',
  '15.2(1)E3',
  '15.2(1)EY',
  '15.2(1)GC',
  '15.2(1)GC1',
  '15.2(1)GC2',
  '15.2(1)S',
  '15.2(1)S1',
  '15.2(1)S2',
  '15.2(1)SC1a',
  '15.2(1)SD1',
  '15.2(1)SD2',
  '15.2(1)SD3',
  '15.2(1)SD4',
  '15.2(1)SD6',
  '15.2(1)SD6a',
  '15.2(1)SD7',
  '15.2(1)SD8',
  '15.2(1)SY',
  '15.2(1)SY0a',
  '15.2(1)SY1',
  '15.2(1)SY1a',
  '15.2(1)SY2',
  '15.2(1)SY3',
  '15.2(1)SY4',
  '15.2(1)SY5',
  '15.2(1)SY6',
  '15.2(1)SY7',
  '15.2(2)E',
  '15.2(2)E1',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(2)E5a',
  '15.2(2)E5b',
  '15.2(2)E6',
  '15.2(2)E7',
  '15.2(2)E7b',
  '15.2(2)E8',
  '15.2(2)E9',
  '15.2(2)E9a',
  '15.2(2)EA',
  '15.2(2)EA1',
  '15.2(2)EA2',
  '15.2(2)EA3',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.2(2)GC',
  '15.2(2)JAX1',
  '15.2(2)JN1',
  '15.2(2)JN2',
  '15.2(2)S',
  '15.2(2)S0a',
  '15.2(2)S0c',
  '15.2(2)S0d',
  '15.2(2)S1',
  '15.2(2)S2',
  '15.2(2)SC',
  '15.2(2)SC1',
  '15.2(2)SC3',
  '15.2(2)SC4',
  '15.2(2)SY',
  '15.2(2)SY1',
  '15.2(2)SY2',
  '15.2(2)SY3',
  '15.2(2a)E1',
  '15.2(2a)E2',
  '15.2(2b)E',
  '15.2(3)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(3)E4',
  '15.2(3)E5',
  '15.2(3)EA',
  '15.2(3)EA1',
  '15.2(3)GC',
  '15.2(3)GC1',
  '15.2(3a)E',
  '15.2(3m)E2',
  '15.2(3m)E7',
  '15.2(3m)E8',
  '15.2(4)E',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(4)E3',
  '15.2(4)E4',
  '15.2(4)E5',
  '15.2(4)E5a',
  '15.2(4)E6',
  '15.2(4)E7',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(4)EA2',
  '15.2(4)EA3',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.2(4)EA7',
  '15.2(4)EA8',
  '15.2(4)EC1',
  '15.2(4)EC2',
  '15.2(4)GC',
  '15.2(4)GC1',
  '15.2(4)GC2',
  '15.2(4)GC3',
  '15.2(4)JAZ1',
  '15.2(4)JN1',
  '15.2(4)M',
  '15.2(4)M1',
  '15.2(4)M10',
  '15.2(4)M11',
  '15.2(4)M2',
  '15.2(4)M3',
  '15.2(4)M4',
  '15.2(4)M5',
  '15.2(4)M6',
  '15.2(4)M6a',
  '15.2(4)M6b',
  '15.2(4)M7',
  '15.2(4)M8',
  '15.2(4)M9',
  '15.2(4)S',
  '15.2(4)S0c',
  '15.2(4)S1',
  '15.2(4)S1c',
  '15.2(4)S2',
  '15.2(4)S3',
  '15.2(4)S3a',
  '15.2(4)S4',
  '15.2(4)S4a',
  '15.2(4)S5',
  '15.2(4)S6',
  '15.2(4)S7',
  '15.2(4)S8',
  '15.2(4a)EA5',
  '15.2(4m)E1',
  '15.2(4m)E2',
  '15.2(4m)E3',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(4o)E3',
  '15.2(4p)E1',
  '15.2(4q)E1',
  '15.2(4s)E1',
  '15.2(4s)E2',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EA',
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
  '15.3(0)SY',
  '15.3(1)S',
  '15.3(1)S1',
  '15.3(1)S1e',
  '15.3(1)S2',
  '15.3(1)SY',
  '15.3(1)SY1',
  '15.3(1)SY2',
  '15.3(1)T',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.3(1)T3',
  '15.3(1)T4',
  '15.3(2)S',
  '15.3(2)S1',
  '15.3(2)S2',
  '15.3(2)T',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.3(2)T3',
  '15.3(2)T4',
  '15.3(3)JAA1',
  '15.3(3)M',
  '15.3(3)M1',
  '15.3(3)M10',
  '15.3(3)M2',
  '15.3(3)M3',
  '15.3(3)M4',
  '15.3(3)M5',
  '15.3(3)M6',
  '15.3(3)M7',
  '15.3(3)M8',
  '15.3(3)M8a',
  '15.3(3)M9',
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S10',
  '15.3(3)S1a',
  '15.3(3)S2',
  '15.3(3)S2a',
  '15.3(3)S3',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.3(3)S6',
  '15.3(3)S6a',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(3)S8a',
  '15.3(3)S9',
  '15.3(3)XB12',
  '15.4(1)CG',
  '15.4(1)CG1',
  '15.4(1)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(1)S3',
  '15.4(1)S4',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.4(1)T',
  '15.4(1)T1',
  '15.4(1)T2',
  '15.4(1)T3',
  '15.4(1)T4',
  '15.4(2)CG',
  '15.4(2)S',
  '15.4(2)S1',
  '15.4(2)S2',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(2)SN',
  '15.4(2)SN1',
  '15.4(2)T',
  '15.4(2)T1',
  '15.4(2)T2',
  '15.4(2)T3',
  '15.4(2)T4',
  '15.4(3)M',
  '15.4(3)M1',
  '15.4(3)M10',
  '15.4(3)M2',
  '15.4(3)M3',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(3)M6',
  '15.4(3)M6a',
  '15.4(3)M7',
  '15.4(3)M7a',
  '15.4(3)M8',
  '15.4(3)M9',
  '15.4(3)S',
  '15.4(3)S0d',
  '15.4(3)S0e',
  '15.4(3)S0f',
  '15.4(3)S1',
  '15.4(3)S10',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(3)S6',
  '15.4(3)S6a',
  '15.4(3)S7',
  '15.4(3)S8',
  '15.4(3)S9',
  '15.4(3)SN1',
  '15.4(3)SN1a',
  '15.5(1)S',
  '15.5(1)S1',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(1)S4',
  '15.5(1)SN',
  '15.5(1)SN1',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.5(1)SY2',
  '15.5(1)T',
  '15.5(1)T1',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(1)T4',
  '15.5(2)S',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(2)S3',
  '15.5(2)S4',
  '15.5(2)SN',
  '15.5(2)T',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.5(2)T4',
  '15.5(2)XB',
  '15.5(3)M',
  '15.5(3)M0a',
  '15.5(3)M1',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M5',
  '15.5(3)M5a',
  '15.5(3)M6',
  '15.5(3)M6a',
  '15.5(3)M7',
  '15.5(3)M8',
  '15.5(3)S',
  '15.5(3)S0a',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)S3',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S6b',
  '15.5(3)S7',
  '15.5(3)S8',
  '15.5(3)SN',
  '15.5(3)SN0a',
  '15.6(1)S',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(1)S3',
  '15.6(1)S4',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(1)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(1)T2',
  '15.6(1)T3',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(2)S2',
  '15.6(2)S3',
  '15.6(2)S4',
  '15.6(2)SN',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3',
  '15.6(2)SP3b',
  '15.6(2)SP4',
  '15.6(2)SP5',
  '15.6(2)T',
  '15.6(2)T0a',
  '15.6(2)T1',
  '15.6(2)T2',
  '15.6(2)T3',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b',
  '15.9(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['hsrp_v2']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj98575',
  'cmds'     , make_list('show standby')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
