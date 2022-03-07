#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127118);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/05  5:45:36");

  script_cve_id("CVE-2019-1873");
  script_bugtraq_id(109123);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvp36425");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190710-asa-ftd-dos");
  script_xref(name: "IAVA", value: "2019-A-0271");

  script_name(english:"Cisco ASA and FTD Software Cryptographic TLS and SSL Driver Denial of Service Vulnerability (cisco-sa-20190710-asa-ftd-dos)");
  script_summary(english:"Checks the version of Adaptive Security Appliance Software and Cisco Firepower Threat Defense Software.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Adaptive Security Appliance Software or
Cisco Firepower Threat Defense Software is affected by a vulnerability in the cryptographic
driver, which could could allow an unauthenticated, remote attacker to cause the device to reboot unexpectedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190710-asa-ftd-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp36425");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1873");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
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
include('cisco_workarounds.inc');
include('ccf.inc');
include('cisco_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

asa_ver = get_kb_item_or_exit('Host/Cisco/ASA');
asa_ver = extract_asa_version(asa_ver);
asa_model = get_kb_item_or_exit('Host/Cisco/ASA/model');
show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
ftd = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (asa_model !~ '^55(06|08|16)-X' || isnull(ftd)) audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

ftd_ver = ftd[1];
vuln_asa = FALSE;
ftd_fix = '';

if (asa_ver =~'^9\\.12' && check_asa_release(version:asa_ver, patched:'9.12(2)')) vuln_asa = TRUE;
else if (asa_ver =~'^9\\.10' && check_asa_release(version:asa_ver, patched:'9.10(1.22)')) vuln_asa = TRUE;
else if (asa_ver =~'^9\\.9' && check_asa_release(version:asa_ver, patched:'9.9(2.52)')) vuln_asa = TRUE;
else if (asa_ver =~'^9\\.[78]' && check_asa_release(version:asa_ver, patched:'9.8(4.3)')) vuln_asa = TRUE;
else if (asa_ver =~'^9\\.[56]' && check_asa_release(version:asa_ver, patched:'9.6(4.29)')) vuln_asa = TRUE;
else if (check_asa_release(version:asa_ver, patched:'9.4(4.36)')) vuln_asa = TRUE;

if (ftd_ver =~ '^6\\.4') ftd_fix = '6.4.0.2';
else if (ftd_ver =~ '^6\\.3') ftd_fix = '6.3.0.4';
else ftd_fix = '6.2.3.13';

if ((ver_compare(ver:ftd_ver, fix:ftd_fix, strict:FALSE) >= 0) && !vuln_asa) audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Bug               : CSCvp36425' +
  '\n  ASA version       : ' + asa_ver +
  '\n  FTD version       : ' + ftd_ver;
security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
