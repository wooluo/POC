#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126646);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/12 16:55:49");

  script_cve_id("CVE-2019-1886");
  script_bugtraq_id(109049);
  script_xref(name:"IAVA", value:"2019-A-0219");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvo33747");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190703-wsa-dos");

  script_name(english:"Cisco Web Security Appliance HTTPS Certificate Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Web Security Appliance (WSA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by a denial of service
vulnerability in the HTTPS decryption feature of WSA due to insufficient validation. An unauthenticated, remote attacker
can exploit this, by installing a malformed certificate in a web server and sending a request to it through the Cisco
WSA to cause a denial of service condition.
");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-wsa-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo33747");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1886");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance_(wsa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');

# Granularity check
if (
  ver == '10' || ver == '10.5' || ver == '10.5.2' ||
  ver == '11' || ver == '11.5' || ver == '11.5.0'
) audit(AUDIT_VER_NOT_GRANULAR, 'Cisco Web Security Appliance', ver);

display_fix = FALSE;

# Prior to 10.5
if (ver =~ "^[0-9]($|[^0-9])" || ver =~ "^10\.[0-4]($|[^0-9])")
  display_fix = '10.5.5-005';

# 10.5.x < 10.5.5.005 
else if (
  ver =~ "^10\.5\.[0-4]($|[^0-9])" ||
  ver =~ "^10\.5\.5\.(0|(00[0-4]))($|[^0-9])"
)
  display_fix = '10.5.5-005';

# 11.5.x  < 11.5.2.020
else if (
  ver =~ "^11\.5\.[0-1]($|[^0-9])" ||
  ver =~ "^11\.5\.2\.(0|0[0-1][0-9])($|[^0-9])"
)
  display_fix = '11.5.2-020';

else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

if (display_fix)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Solution          : ' + display_fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);
