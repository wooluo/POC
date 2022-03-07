#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126599);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/10 16:42:56");

  script_cve_id("CVE-2019-1594");
  script_bugtraq_id(107325);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi93959");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj22443");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj22446");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj22447");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj22449");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190306-nx-os-lan-auth");

  script_name(english:"Cisco NX-OS Software 802.1X Extensible Authentication Protocol over LAN Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a distributed denial of service (DDoS) vulnerability exists in the 802.1X
implementation for Cisco NX-OS Software due to incomplete input validation of EAPOL frames. An unauthenticated,
remote attacker can exploit this by sending a crafted EAPOL frame to an interface on the targeted device to cause
system-level restart of the device and denial of service condition.");
# https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nx-os-lan-auth
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi93959");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22443");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22446");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22447");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22449");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi93959, CSCvj22443, CSCvj22446, CSCvj22447,
CSCvj22449");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1594");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os_for_nexus_9000_series_fabric_switches_aci_mode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^10[0-9][0-9]V')
    cbi = 'CSCvj22447';
 if (product_info.model =~ '^(3[05]|90)[0-9][0-9]')
    cbi = 'CSCvj22443, CSCvj22446';
  if (product_info.model =~ '^([26]0|5[56])[0-9][0-9]')
    cbi = 'CSCvj22449';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvi93959';
}
if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '4.0(1a)N1(1)',
  '4.0(1a)N1(1a)',
  '4.0(1a)N2(1)',
  '4.0(1a)N2(1a)',
  '4.2(1)N1(1)',
  '4.2(1)N2(1)',
  '4.2(1)N2(1a)',
  '4.2(1)SV1(4)',
  '4.2(1)SV1(4a)',
  '4.2(1)SV1(4b)',
  '4.2(1)SV1(5.1)',
  '4.2(1)SV1(5.1a)',
  '4.2(1)SV1(5.2)',
  '4.2(1)SV1(5.2b)',
  '4.2(1)SV2(1.1)',
  '4.2(1)SV2(1.1a)',
  '4.2(1)SV2(2.1)',
  '4.2(1)SV2(2.1a)',
  '4.2(1)SV2(2.2)',
  '4.2(1)SV2(2.3)',
  '5.0(2)N1(1)',
  '5.0(2)N2(1)',
  '5.0(2)N2(1a)',
  '5.0(3)N1(1)',
  '5.0(3)N1(1a)',
  '5.0(3)N1(1b)',
  '5.0(3)N1(1c)',
  '5.0(3)N2(1)',
  '5.0(3)N2(2)',
  '5.0(3)N2(2a)',
  '5.0(3)N2(2b)',
  '5.1(3)N1(1)',
  '5.1(3)N1(1a)',
  '5.1(3)N2(1)',
  '5.1(3)N2(1a)',
  '5.1(3)N2(1b)',
  '5.1(3)N2(1c)',
  '5.2(1)',
  '5.2(1)N1(1)',
  '5.2(1)N1(1a)',
  '5.2(1)N1(1b)',
  '5.2(1)N1(2)',
  '5.2(1)N1(2a)',
  '5.2(1)N1(3)',
  '5.2(1)N1(4)',
  '5.2(1)N1(5)',
  '5.2(1)N1(6)',
  '5.2(1)N1(7)',
  '5.2(1)N1(8)',
  '5.2(1)N1(8a)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(9)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9b)',
  '5.2(1)SV3(1.1)',
  '5.2(1)SV3(1.2)',
  '5.2(1)SV3(1.3)',
  '5.2(1)SV3(1.3a)',
  '5.2(1)SV3(1.3b)',
  '5.2(1)SV3(1.3c)',
  '5.2(1)SV3(1.4)',
  '5.2(3)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(9)N1(1)',
  '5.2(9a)',
  '6.0(2)N1(1)',
  '6.0(2)N1(1a)',
  '6.0(2)N1(2)',
  '6.0(2)N1(2a)',
  '6.0(2)N2(1)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(2)',
  '6.0(2)N2(3)',
  '6.0(2)N2(4)',
  '6.0(2)N2(5)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(6)',
  '6.0(2)N2(7)',
  '6.1(1)',
  '6.1(2)',
  '6.1(3)',
  '6.1(3)S5',
  '6.1(3)S6',
  '6.1(4)',
  '6.1(4a)',
  '6.1(5)',
  '6.1(5a)',
  '6.2(10)',
  '6.2(12)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(14b)',
  '6.2(16)',
  '6.2(18)',
  '6.2(2)',
  '6.2(20)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6a)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(2)N1(1)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)N1(1)',
  '7.0(4)N1(1)',
  '7.0(5)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(6)N1(1)',
  '7.0(7)N1(1)',
  '7.0(8)N1(1)',
  '7.1(0)N1(1)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(1)N1(1)',
  '7.1(2)N1(1)',
  '7.1(3)N1(1)',
  '7.1(3)N1(2.1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(3.12)',
  '7.1(4)N1(1)',
  '7.1(5)N1(1)',
  '7.2(0)D1(0.437)',
  '7.2(0)D1(1)',
  '7.2(0)N1(1)',
  '7.2(0)ZZ(99.1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.2(2)D1(1)',
  '7.2(2)D1(2)',
  '7.3(0.2)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)N1(1)',
  '7.3(1)D1(1)',
  '7.3(1)D1(1B)',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)',
  '7.3(3)N1(1)',
  '7.3(4)N1(1)',
  '8.0(1)',
  '8.0(1)S2',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['nxos_dot1x']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
