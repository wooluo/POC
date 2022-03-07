#TRUSTED 43d3f249ab73f2c65a1eb3f448d5ee3df65e04444ef16878f6e6498884843d6b89332bfbf2a07f15d8a3523c4f57ce411069c610050ff58bf47b3112b0a2b66d7a1487efabfb75fd753798a037197b45120b754ffb62372b0e5566ccc70de7f7eee0a15d40f5da20800ad369eb69171dc5ae3987b2fb492799416b85068bc1223660c5171b6fbb8f85d8d0e7f44e738a2653b6198842477eabf170cf4fe73a67f6ef003b06d2eda517b28aef6fb8327c71ae74d41116607ae66cdd7ee7f37830397936548ed2aaf30e2e58c9304ee1605ec61e07488df5bfe0127059d399d5b80eb7451f92283c38eca0fc74c7c48cc74ebfb0ffbff6aa6834669b1d1fdefcc114a3f5767c9c24c9aca19e86a4828587eecd7d1b0adc3802e3a4ae2523a7e49d7fd7acfe2c67e8745afa55141b3bf966365fa44f67e58be4d1eb9dc2c45c49db40a84108649a1c81ab0a58032ff7e31c39606b64ac613fcbbc75673eba9a772db12f959d261520b83c5b2449ec4cb122173426904054ee653e9f471a81894982061a148d643c64ce0d35ac4121334179f1c6c6a06f7741790ae58ba186e212494c39f3051ecc0bb000bfa5bb7cc5c4667eb57c4b6ff2620e662d59a3fc01965cd9be29f0ca471eeb15b1bbed713d354380972a1b702a191a9fb7ff063c06dc3fc72c5fa64b5e46c834ff9d879b13ba09faa86654ff238de6d5070a888ea3d8ab
#
# 
#

include('compat.inc');

if (description)
{
  script_id(140185);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2020-3415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr89315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-dme-rce-cbE3nhZS");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco NX-OS Software Data Management Engine Remote Code Execution (cisco-sa-nxos-dme-rce-cbE3nhZS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a remote code execution vulnerability. The
vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a
crafted Cisco Discovery Protocol packet to a Layer 2-adjacent affected device. A successful exploit could allow the
attacker to execute arbitrary code with administrative privileges or cause the Cisco Discovery Protocol process to
crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dme-rce-cbE3nhZS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f83e12a0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr89315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr89315");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3415");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
cbi = '';

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^9[0-9]{3}")
  {
    cbi = 'CSCvr89315';
    version_list = make_list(
      '7.0(3)F1(1)',
      '7.0(3)F2(1)',
      '7.0(3)F2(2)',
      '7.0(3)F3(1)',
      '7.0(3)F3(3)',
      '7.0(3)F3(3a)',
      '7.0(3)F3(4)',
      '7.0(3)F3(3c)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)I7(2)',
      '7.0(3)I7(3)',
      '7.0(3)I7(4)',
      '7.0(3)I7(5)',
      '7.0(3)I7(5a)',
      '7.0(3)I7(3z)',
      '7.0(3)I7(6)',
      '7.0(3)I7(7)',
      '9.2(1)',
      '9.2(2)',
      '7.0(3)IA7(1)',
      '7.0(3)IA7(2)'
    );
  }
  else if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCvr89315';
    version_list = make_list(
      '7.0(3)F3(1)',
      '7.0(3)F3(2)',
      '7.0(3)F3(3)',
      '7.0(3)F3(3a)',
      '7.0(3)F3(4)',
      '7.0(3)F3(3c)',
      '7.0(3)F3(5)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)I7(2)',
      '7.0(3)I7(3)',
      '7.0(3)I7(4)',
      '7.0(3)I7(5)',
      '7.0(3)I7(5a)',
      '7.0(3)I7(3z)',
      '7.0(3)I7(6)',
      '7.0(3)I7(6z)',
      '7.0(3)I7(7)',
      '9.2(1)', 
      '9.2(2)',
      '9.2(2t)', 
      '9.2(2v)', 
      '7.0(3)IM7(2)'
    );
  }
}

if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'an affected model');

workarounds = make_list(CISCO_WORKAROUNDS['nxos_cdp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);