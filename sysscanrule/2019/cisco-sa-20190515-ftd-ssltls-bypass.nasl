#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126310);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/05  9:28:46");

  script_cve_id("CVE-2019-1833");
  script_bugtraq_id(108338);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi81022");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190515-ftd-ssltls-bypass");

  script_name(english:"Cisco Firepower Threat Defense Software SSL/TLS Policy Bypass Vulnerability");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense
Software is affected by following vulnerability

  - A vulnerability in the Secure Sockets Layer
    (SSL)/Transport Layer Security (TLS) protocol parser of
    Cisco Firepower Threat Defense (FTD) Software could
    allow an unauthenticated, remote attacker to bypass
    configured policies.The vulnerability is due to improper
    parsing of specific attributes in a TLS packet header.
    An attacker could exploit this vulnerability by sending
    malicious  TLS messages to the affected system. A
    successful exploit could allow the attacker to bypass
    the configured policies for the system, which could
    allow traffic to flow through without being inspected.
    (CVE-2019-1833)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-ftd-ssltls-bypass
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi81022");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi81022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1833");
  script_cwe_id(693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");
if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, 'affected');

if (
  fdm_ver[1] =~ "6.1.0" ||
  fdm_ver[1] =~ "6.2.0" ||
  fdm_ver[1] =~ "6.2.1" ||
  fdm_ver[1] =~ "6.2.2" ||
  fdm_ver[1] =~ "6.3.0"
  )
{
  report =
  '\n  Bug               : CSCvi81022' +
  '\n  Installed version : ' + fdm_ver[1] +
  '\n  Fix               : See advisory';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
} else audit(AUDIT_HOST_NOT, 'affected');
