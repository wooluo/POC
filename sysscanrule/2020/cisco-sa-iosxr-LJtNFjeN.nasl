#TRUSTED 5370ed4fea348ac2f6dba184d934f68e9b5656bca086411d52137f94e661af64e74d0c6a8d201c8e2315b54dc961255c923a6e59450d3c457f47f9aa8eab7f292f6a2f3aa90af07cb9134f2d8b09e07353d4e9fcdc790e7f86240be21061f4172bd098ad748c187c0b372b2e93f3c1d08804128db865b2904376e29f2d894e60d946b2e5622dda67bd6afcb6fda10e507d46bd719acb698fb9172d1be47f44849d17b4e56f09abb4aeb4c1cc544ac18fd7c194bd4e97db717a8394f8f4de042b9c3a18f3a48fd757fd48b168f4aa37ce761b5624f4aa20d121f6f578ac180cbf75b9826db0fe3164457812e4171d755013f2d0c477cd427e6d8dcfc867cb2fc7022f794646ead327bac64b1f81e9ed336c03984bffd47427a9c780ca23f9870728832ac633a3b311148ac4488cad5809c4beb07ccc95ab26e8a73e43c20c25b0dfa86fa65ceea1fb607739fea886fdd3d95bfbb468f5cbed644ad77af67dc2559fe96eb863d8d5eef4681a046fceafaa659a7255baf052f6c8b54aa0b65d0affb03ff2a4c01c331ca3d123ca39a8313acbba60b43ccd186c505298a51ad1c76aed8c1eac2ef22780201dc962ba3eba52e695a533fa46adbc7960f0a78c210a372c49fb28ff1d629e888e0c41f9137fb69691be2e9e1fd290c2f97abe534523c6efa040e28c82e1fb8361f3850649d068e1527f5076d041cbf246653bf0ac5dd0
#
# 
#

include('compat.inc');

if (description)
{
  script_id(140793);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2020-3473");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs12604");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-LJtNFjeN");
  script_xref(name:"IAVA", value:"2020-A-0374");

  script_name(english:"Cisco IOS XR Software Authenticated User Privilege Escalation (cisco-sa-iosxr-LJtNFjeN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a privilege escalation vulnerability in
task group assignment for a specific CLI command due to incorrect mapping to task groups. An attacker could exploit
this vulnerability by first authenticating to the local CLI shell on the device and using the CLI command to bypass
the task group–based checks. A successful exploit could allow the attacker to elevate privileges and gain full
administrative control of the device. There are workarounds that address this vulnerability.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-LJtNFjeN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d85a259");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs12604");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs12604");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3473");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

if (model =~ "8[0-9]{3}") // 8000 Series Routers
{
  vuln_ranges = [
    { 'min_ver' : '5', 'fix_ver' : '7.0.12' },
    { 'min_ver' : '7.2', 'fix_ver' : '7.2.1' }
  ];
}
else if ("NCS4K" >< model || model =~ "NCS4[0-9]{3}") // Network Convergence System 4000 Series
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '6.6.3' }
  ];
  smus['6.5.29'] = 'CSCvs12604';
}
else if (
     'XRV9K' >< model || model =~ "XRV9[0-9]{3}" || "XRV 9" >< model // IOS XRv 9000 Router
  || 'NCS540' >< model || 'NCS560' >< model // Network Convergence System 540/560 Routers
  || 'NCS55' >< model || model =~ "NCS55[0-9]{2}" // Network Convergence System 5500 Series
  || 'NCS6K' >< model || model =~ "NCS6[0-9]{3}") // Network Convergence System 6000 Series
{
  vuln_ranges = [
    { 'min_ver' : '5', 'fix_ver' : '6.6.3' },
    { 'min_ver' : '7.0', 'fix_ver' : '7.0.2' },
    { 'min_ver' : '7.1', 'fix_ver' : '7.1.1' }
  ];
}
else audit(AUDIT_HOST_NOT, 'an affected model');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs12604'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
