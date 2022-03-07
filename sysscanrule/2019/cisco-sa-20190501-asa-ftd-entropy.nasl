#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126341);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/05  9:28:46");

  script_cve_id("CVE-2019-1715");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj52266");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190501-asa-ftd-entropy");

  script_name(english:"Cisco Adaptive Security Appliance Software and Firepower Threat Defense Software Low-Entropy Keys Vulnerability");
  script_summary(english:"Checks the version of Adaptive Security Appliance Software and Cisco Firepower Threat Defense Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Adaptive Security Appliance Software or Cisco Firepower Threat Defense Software
is affected by a vulnerability in the Deterministic Random Bit Generator (DRBG), alsoknown as Pseudorandom Number
Generator (PRNG), used in Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD)
Software could allow an unauthenticated, remote attacker to cause acryptographic collision, enabling the attacker to
discover the private key of an affected device. The vulnerability is due to insufficient entropy in the DRBG when
generating cryptographic keys. An attacker could exploit this vulnerability by generating a large number of cryptographic
keys on an affected device and looking for collisions with target devices. A successful exploit could allow the attacker
to impersonate an affected target device or to decrypt traffic secured byan affected key that is sent to or from an
affected target device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-ftd-entropy
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj52266");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj52266");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1715");
  script_cwe_id(332);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");
include("obj.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln = FALSE;

asa_ver = get_kb_item_or_exit('Host/Cisco/ASA');
asa_ver = extract_asa_version(asa_ver);
show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');

if (
  asa_ver == '9.8' ||
  asa_ver == '9.9'
) vuln = TRUE;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(fdm_ver) && !vuln) audit(AUDIT_HOST_NOT, "affected");

if (
  fdm_ver[1] == '6.2.1' ||
  fdm_ver[1] == '6.2.2' ||
  fdm_ver[1] == '6.2.3'
) vuln = TRUE;

if (vuln)
{
  report =
    '\n  Bug         : CSCvj52266' +
    '\n  ASA Version : ' + asa_ver +
    '\n  FTD version : ' + fdm_ver[1];
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
} else audit(AUDIT_HOST_NOT, "affected");
