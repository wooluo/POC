#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124277);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/24 14:38:14");

  script_cve_id("CVE-2019-1746");
  script_xref(name: "CWE", value: "CWE-20");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj25068");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj25124");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-cmp-dos");

  script_name(english:"Cisco IOS and IOS XE Software Cluster Management Protocol Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by A vulnerability in the Cluster Management
Protocol (CMP) processing code in Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, adjacent
attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient
input validation when processing CMP management packets. An attacker could exploit this vulnerability by sending
malicious CMP management packets to an affected device. A successful exploit could cause the switch to crash, resulting
in a DoS condition. The switch will reload automatically.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-cmp-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj25124");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj25124");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1746");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  "3.9.2bE",
  "3.9.2E",
  "3.9.1E",
  "3.9.0E",
  "3.8.7E",
  "3.8.6E",
  "3.8.5aE",
  "3.8.5E",
  "3.8.4E",
  "3.8.3E",
  "3.8.2E",
  "3.8.1E",
  "3.8.0E",
  "3.7.5E",
  "3.7.4E",
  "3.7.3E",
  "3.7.2E",
  "3.7.1E",
  "3.7.0E",
  "3.6.9E",
  "3.6.8E",
  "3.6.7bE",
  "3.6.7aE",
  "3.6.7E",
  "3.6.6E",
  "3.6.5bE",
  "3.6.5aE",
  "3.6.5E",
  "3.6.4E",
  "3.6.3E",
  "3.6.2aE",
  "3.6.2E",
  "3.6.1E",
  "3.6.10E",
  "3.6.0bE",
  "3.6.0aE",
  "3.6.0E",
  "3.5.8SQ",
  "3.5.7SQ",
  "3.5.6SQ",
  "3.5.5SQ",
  "3.5.4SQ",
  "3.5.3SQ",
  "3.5.3E",
  "3.5.2SQ",
  "3.5.2E",
  "3.5.1SQ",
  "3.5.1E",
  "3.5.0SQ",
  "3.5.0E",
  "3.4.8SG",
  "3.4.7SG",
  "3.4.6SG",
  "3.4.5SG",
  "3.4.4SG",
  "3.4.3SG",
  "3.4.2SG",
  "3.4.1SQ",
  "3.4.1SG",
  "3.4.0SQ",
  "3.4.0SG",
  "3.3.2XO",
  "3.3.2SG",
  "3.3.1XO",
  "3.3.1SQ",
  "3.3.1SG",
  "3.3.0XO",
  "3.3.0SQ",
  "3.3.0SG",
  "3.2.9SG",
  "3.2.8SG",
  "3.2.7SG",
  "3.2.6SG",
  "3.2.5SG",
  "3.2.4SG",
  "3.2.3SG",
  "3.2.2SG",
  "3.2.1SG",
  "3.2.11SG",
  "3.2.10SG",
  "3.2.0SG",
  "3.16.1S",
  "3.16.10S",
  "3.16.0bS",
  "3.12.0aS",
  "3.10.4S",
  "3.10.1sE",
  "3.10.1aE",
  "3.10.1E",
  "3.10.0cE",
  "3.10.0E",
  "16.9.2h",
  "16.12.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['cluster']);
workaround_params = {'is_configured' : 1};

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , "CSCvj25068, CSCvj25124"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
