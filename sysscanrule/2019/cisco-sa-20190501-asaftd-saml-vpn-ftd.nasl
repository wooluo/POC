#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128064);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/22 12:01:11");

  script_cve_id("CVE-2019-1714");
  script_bugtraq_id(108185);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn72570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asaftd-saml-vpn");
  script_xref(name:"IAVA", value:"2019-A-0271");

  script_name(english:"Cisco Firepower Threat Defense (FTD) VPN SAML Authentication Bypass Vulnerability (cisco-sa-20190501-asaftd-saml-vpn)");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense Software.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Threat
Defense (FTD) Software is affected by an authentication bypass
vulnerability in the implementation of Security Assertion Markup
Language (SAML) 2.0 Single Sign-On (SSO) for Clientless SSL VPN
(WebVPN) and AnyConnect Remote Access VPN. The vulnerability is due
to improper credential management when using NT LAN Manager (NTLM)
or basic authentication. An attacker could exploit this vulnerability
by opening a VPN session to an affected device after another VPN user
has successfully authenticated to the affected device via SAML SSO.
A successful exploit could allow the attacker to connect to secured
networks behind the affected device. (CVE-2019-1714)

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asaftd-saml-vpn
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn72570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvn72570");
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
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/show_ver", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');

app = 'Cisco Firepower Threat Defense';
fix = NULL;

ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(ver)) audit(AUDIT_HOST_NOT, app);

ver = ver[1];

if (ver =~ "^6\.2\.[123]($|\.)")
  fix = '6.2.3.12';
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Bugs              : CSCvn72570' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
} else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
