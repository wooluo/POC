#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128063);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/22 12:01:11");

  script_cve_id("CVE-2019-1714");
  script_bugtraq_id(108185);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn72570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asaftd-saml-vpn");
  script_xref(name:"IAVA", value:"2019-A-0271");

  script_name(english:"Cisco Adaptive Security Appliance VPN SAML Authentication Bypass Vulnerability (cisco-sa-20190501-asaftd-saml-vpn)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
an authentication bypass vulnerability in the implementation of
Security Assertion Markup Language (SAML) 2.0 Single Sign-On (SSO)
for Clientless SSL VPN (WebVPN) and AnyConnect Remote Access VPN.
The vulnerability is due to improper credential management when using
NT LAN Manager (NTLM) or basic authentication. An attacker could
exploit this vulnerability by opening a VPN session to an affected
device after another VPN user has successfully authenticated to the
affected device via SAML SSO. A successful exploit could allow the
attacker to connect to secured networks behind the affected device.
(CVE-2019-1714)

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asaftd-saml-vpn
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn72570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvn72570.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1714");
  script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:"Cisco Adaptive Security Appliance (ASA) Software");

if (
  product_info.model !~ '^30[0-9][0-9]($|[^0-9])' && # 3000 ISA
  product_info.model !~ '^55[0-9][0-9]-X' && # 5500-X
  product_info.model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  product_info.model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  product_info.model != 'v' &&                       # ASAv
  product_info.model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  product_info.model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower 4100 SSA
  product_info.model !~ '^93[0-9][0-9]($|[^0-9])'    # Firepower 9300 ASA
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

vuln_ranges = [
  {'min_ver' : '9.7',  'fix_ver' : '9.8(4)'},
  {'min_ver' : '9.8',  'fix_ver' : '9.8(4)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.50)'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10(1.17)'}
];

workarounds = make_list(CISCO_WORKAROUNDS['show_webvpn_saml_idp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn72570'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
