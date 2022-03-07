#TRUSTED 2f13d99bb65dc0c75867c85efde41ec07d76b3280e4024776defa1777db74ced326dea044d53f66ae425b933d56a86f9c6a5d72202ed181345ff042f3f7639c53d8d48720ce0e2cc16824bb4efb85f0080a9e965f29f92cb50d69d30c84517518924310b960ad127611b092caf491157974535d0b6c12900fa1ee53cfc2cfbd050d648ebe3a8cae060d0ed4389e42541509dabd7231a1b64b3a6aed53eea0b9b390ee84507692080d28a753ec9b29c8a37040cb1234df59d92dc37514e35c881371d9d93dbf22e54c60a77a855b59fb1aaca1db17d0b09400180acce00627fa357b8808edfc07b3aa56993aae6b12b3b96f0a64a2296423b0be0b8edfe95911df8aaa4a1a9a8e46d0bf7453c0b053a72c1410c222119474015d8a6d65dc93c88aee92c255883140ff756dc7beccff421066e76a16952841fdc33ac23e8dd76cde259b2884f6d74d6fc9bc49ffc8bf2c6bae251bfe4c3f7f588481095d6f20e5ce0751ec158cdbcc85c2e32aa26e1be0d0bbf112846a9a2f06b0cfe637ccb07d07dba07496b7d47ad1cc2fbd7d5ce0cc7d3915fefbdb7202072aa6761cad0210feee6ec0e166ad0a7c9a36341836864864a5d5193c8ff54400e01585628a166f9f038a09e59180c86f3c7feb1b7a055dae17d6cf124a1828b9f99dde888f81deefa8bfbedc4a3869dddb80fe8def30da694a58b0d96971a79d9e887dcfe337e4a
#
# 
#

include('compat.inc');

if (description)
{
  script_id(139850);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/27");

  script_cve_id("CVE-2019-12661");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw36015");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-vman-cmd-injection");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Virtualization Manager CLI Command Injection Vulnerability (cisco-sa-20190925-vman-cmd-injection)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by command injection vulnerability. A local,
authenticated attacker can exploit this to execute arbitrary code as root on the underlying system.  Please see the
included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-vman-cmd-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39d1eeaf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw36015");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuw36015");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12661");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '15.3.3S',
  '15.4.2S',
  '15.4.3S',
  '15.5.1S',
  '15.5.2S',
  '15.5.3S',
  '15.6.1S'
);

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCuw36015'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);

