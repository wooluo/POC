#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128112);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/23 10:14:43");

  script_cve_id("CVE-2019-1982");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj19544");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvq07297");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190816-ftd-http");
  script_xref(name: "IAVA", value: "2019-A-0305");

  script_name(english:"Cisco Firepower Threat Defense Software HTTP Filtering Bypass Vulnerability (cisco-sa-20190816-ftd-http)");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense Software.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by
a vulnerability in the HTTP traffic filtering component due to improper handling of HTTP requests.
An attacker may exploit this vulnerability by sending malicious requests to an affected device,
which would allow them to bypass filtering and deliver malicious requests that would otherwise be blocked.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190816-ftd-http
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj19544");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq07297");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj19544 and CSCvq07297");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1982");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/show_ver", "Host/Cisco/ASA/model", "Settings/ParanoidReport");
  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

asa_model = get_kb_item_or_exit('Host/Cisco/ASA/model');
show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
ftd = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");
if (isnull(ftd)) audit(AUDIT_HOST_NOT, 'affected');

report =
  '\n  Bug ID            : CSCvj19544 and CSCvq07297' +
  '\n  ASA model         : ' + asa_model + 
  '\n  FTD version       : ' + ftd[1] +
  '\n  FTD fixed version : Please refer to Bug ID for fixes.';
security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
