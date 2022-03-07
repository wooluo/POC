#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123557);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id("CVE-2018-18065");
  script_bugtraq_id(106265);

  script_name(english:"Palo Alto Networks  < 7.1.23 / 8.0.x < 8.0.16 / 8.1.x < 8.1.7 Denial of Service vulnerability (PAN-SA-2019-0007)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a Denial of Service (DoS) vulnerability.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host
is prior to 7.1.23 or 8.0.x prior to 8.0.16 or 8.1.x prior to 8.1.7.
A denial of service (DoS) vulnerability exists in PAN-OS management
interface due to vulnerabilty exists in SNMP liabrary. An
unauthenticated, REMOTE attacker can exploit this issue, to cause the
SNMP daemon to stop responding.(CVE-2018-18065");
  #https://securityadvisories.paloaltonetworks.com/Home/Detail/144
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.23 / 8.0.16 / 8.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18065");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("vcf.inc");

app_name = "Palo Alto Networks PAN-OS";

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Palo_Alto/Firewall/Full_Version", webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version" : "7.1.23" },
  { "min_version" : "8.0", "fixed_version" : "8.0.16" },
  { "min_version" : "8.1", "fixed_version" : "8.1.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
