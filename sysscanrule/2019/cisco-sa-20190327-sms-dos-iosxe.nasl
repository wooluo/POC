#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128114);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/23 10:20:34");

  script_cve_id("CVE-2019-1747");
  script_cwe_id("CWE-20");
  script_bugtraq_id(107599);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvm07801");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-sms-dos");

  script_name(english:"Cisco IOS XE Software Short Message Service Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installed Cisco IOS XE Software is affected by a vulnerability in its
implementation of the Short Message Service (SMS) handling functionality. This allows an unauthenticated, remote
attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to improper
processing of SMS protocol data units (PDUs) that are encoded with a special character set. An attacker can exploit
this vulnerability by sending a malicious SMS message to an affected device. A successful exploit allows the attacker
to cause the wireless WAN (WWAN) cellular interface module on an affected device to crash, resulting in a DoS condition
that would require manual intervention to restore normal operating conditions.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-sms-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm07801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm07801");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1747");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['sierra_wireless']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvm07801',
'cmds'     , make_list('show inventory | include Sierra Wireless')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);

