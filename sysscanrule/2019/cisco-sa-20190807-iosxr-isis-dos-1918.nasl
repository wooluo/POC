#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127900);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-1910", "CVE-2019-1918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49076");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp90854");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-iosxr-isis-dos-1910");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-iosxr-isis-dos-1918");
  script_xref(name:"IAVA", value:"2019-A-0296");

  script_name(english:"Cisco IOS XR Software Intermediate System-to-Intermediate System Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by multiple vulnerabilities:

  - A vulnerability in the implementation of the Intermediate System-to-Intermediate System (IS-IS)
  routing protocol functionality in Cisco IOS XR Software could allow an unauthenticated attacker
  who is in the same IS-IS area to cause a denial of service (DoS) condition. The vulnerability is
  due to incorrect processing of crafted IS-IS link-state protocol data units (PDUs).
  An attacker could exploit this vulnerability by sending a crafted link-state PDU to an affected
  system to be processed. A successful exploit could allow the attacker to cause all routers within
  the IS-IS area to unexpectedly restart the IS-IS process, resulting in a DoS condition. This
  vulnerability affects Cisco devices if they are running a vulnerable release of Cisco IOS XR
  Software earlier than Release 6.6.3 and are configured with the IS-IS routing protocol. Cisco has
  confirmed that this vulnerability affects both Cisco IOS XR 32-bit Software and Cisco IOS XR 64-bit
  Software. (CVE-2019-1910)

  - A vulnerability in the implementation of Intermediate System-to-Intermediate System (IS-IS)
  routing protocol functionality in Cisco IOS XR Software could allow an unauthenticated attacker
  who is in the same IS-IS area to cause a denial of service (DoS) condition. The vulnerability is
  due to incorrect processing of IS-IS link-state protocol data units (PDUs).
  An attacker could exploit this vulnerability by sending specific link-state PDUs to an affected
  system to be processed. A successful exploit could allow the attacker to cause incorrect calculations
  used in the weighted remote shared risk link groups (SRLG) or in the IGP Flexible Algorithm. It
  could also cause tracebacks to the logs or potentially cause the receiving device to crash the IS-IS
  process, resulting in a DoS condition. (CVE-2019-1918)

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-iosxr-isis-dos-1910
  script_set_attribute(attribute:"see_also", value:"");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-iosxr-isis-dos-1918
  script_set_attribute(attribute:"see_also", value:"");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49076
  script_set_attribute(attribute:"see_also", value:"");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp90854
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvp49076 and CSCvp90854");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1910");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");
  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
   {'min_ver' : '0.0',  'fix_ver' : '6.6.3'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp49076 and CSCvp90854'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
