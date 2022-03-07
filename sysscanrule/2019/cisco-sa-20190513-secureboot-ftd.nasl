#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125341);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/30 16:25:06");

  script_cve_id("CVE-2019-1649");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvn77248");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190513-secureboot");
  script_xref(name: "IAVA", value: "2019-A-0177");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Secure Boot Hardware Tampering Vulnerability (cisco-sa-20190513-secureboot)");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Firepower Threat Defense (FTD) software installed on the remote host is affected by
a vulnerability in the logic that handles access control to one of the hardware components in Cisco's proprietary Secure
Boot implementation could allow an authenticated, local attacker to write a modified firmware image to the component.
This vulnerability affects multiple Cisco products that support hardware-based Secure Boot functionality. The
vulnerability is due to an improper check on the area of code that manages on-premise updates to a Field Programmable
Gate Array (FPGA) part of the Secure Boot hardware implementation. An attacker with elevated privileges and access to
the underlying operating system that is running on the affected device could exploit this vulnerability by writing a
modified firmware image to the FPGA. A successful exploit could either cause the device to become unusable (and require
a hardware replacement) or allow tampering with the Secure Boot verification process, which under some circumstances may
allow the attacker to install and boot a malicious software image.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190513-secureboot
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn77248");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn77248");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1649");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/show_ver", "Settings/ParanoidReport");
  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('global_settings.inc');

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');

app = 'Cisco Firepower Threat Defense';

ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(ver)) audit(AUDIT_HOST_NOT, app);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = ver[1];

if (ver =~ "^6\.4($|\.)")
  fix = '6.4.0.1';
else if (ver =~ "^6\.3($|\.)")
  fix = '6.3.0.3';
else if (ver =~ "^6\.2($|\.)" && ver !~ "^6\.2\.2\.[0-5]$")
  fix = '6.2.2.12';
else
  fix = '6.2.2.5';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Bug               : CSCvn77248' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
} else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
