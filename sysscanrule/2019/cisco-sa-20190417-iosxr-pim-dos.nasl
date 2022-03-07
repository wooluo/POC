#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126100);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/21 16:11:42");

  script_cve_id("CVE-2019-1712");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvg43676");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190417-iosxr-pim-dos");
  script_xref(name:"IAVA", value:"2019-A-0205");

  script_name(english:"Cisco IOS XR Software Protocol Independent Multicast Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is
affected by a vulnerability in the Protocol Independent Multicast
(PIM) feature of Cisco IOS XR Software.  This could allow an 
unauthenticated, remote attacker to cause the PIM process to 
restart, resulting in a denial of service condition on an affected 
device.The vulnerability is due to the incorrect processing of 
crafted AutoRP packets. An attacker could exploit this vulnerability 
by sending crafted packets to port UDP 496 on a reachable IP address 
on the device. A successful exploit could allow the attacker to cause
 the PIM process to restart. (CVE-2019-1712)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-iosxr-pim-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg43676");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg43676");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1712");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");
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

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XR");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '4.0.0',  'fix_ver' : '6.2.3'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.2', 'fix_display': '6.3.2 / 6.4.0'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.1'},
];

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvg43676'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
