#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125775);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/07 11:31:03");

  script_cve_id("CVE-2019-1595");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvn24414");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190306-nexus-fbr-dos");
  script_xref(name:"IAVA", value:"2019-A-0180");

  script_name(english:"Cisco Nexus 5600 and 6000 Series Switches Fibre Channel over Ethernet Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Fibre Channel over
Ethernet (FCoE) protocol implementation in Cisco NX-OS Software could allow an unauthenticated, adjacent attacker to
cause a denial of service (DoS) condition on an affected device. The vulnerability is due to an incorrect allocation of
an internal interface index. An adjacent attacker with the ability to submit a crafted FCoE packet that crosses affected
interfaces could trigger this vulnerability. A successful exploit could allow the attacker to cause a packet loop and
high throughput on the affected interfaces, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nexus-fbr-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn24414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn24414");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1595");
  script_cwe_id(913);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Settings/ParanoidReport");

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ( product_info.device != 'Nexus' ||
   ( product_info.model !~ '^56[0-9][0-9]' &&
     product_info.model !~ '^60[0-9][0-9]' ))
  audit(AUDIT_HOST_NOT, 'affected');

# We cannot test for the full vulnerable condition
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version_list=make_list(
  '7.3(3)N1(1)',
  '7.3(2)N1(1)',
  '7.3(1)N1(1)',
  '7.3(0)N1(1)',
  '7.2(1)N1(1)',
  '7.2(0)N1(1)',
  '7.1(5)N1(1)',
  '7.1(4)N1(1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(1)',
  '7.1(2)N1(1)',
  '7.1(1)N1(1)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1)',
  '7.0(8)N1(1)',
  '7.0(7)N1(1)',
  '7.0(6)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(5)N1(1)',
  '7.0(4)N1(1)',
  '7.0(3)N1(1)',
  '7.0(2)N1(1)',
  '7.0(1)N1(1)',
  '7.0(0)N1(1)',
  '6.0(2)N2(7)',
  '6.0(2)N2(6)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(5)',
  '6.0(2)N2(4)',
  '6.0(2)N2(3)',
  '6.0(2)N2(2)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(1)',
  '6.0(2)N1(2a)',
  '6.0(2)N1(2)',
  '6.0(2)N1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn24414'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
