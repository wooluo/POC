##
# 
##

include('compat.inc');

if (description)
{
  script_id(144303);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/16");

  script_cve_id("CVE-2015-2808");
  script_bugtraq_id(73684);

  script_name(english:"IBM HTTP Server 8.5.0.0 <= 8.5.5.5 / 8.0.0.0 <= 8.0.0.10 / 7.0.0.0 <= 7.0.0.37 Information Disclosure (260001)");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability. The RC4 algorithm, as used in
the TLS protocol and SSL protocol, does not properly combine state data with key data during the initialization phase,
which makes it easier for remote attackers to conduct plaintext-recovery attacks against the initial bytes of a stream
by sniffing network traffic that occasionally relies on keys affected by the Invariance Weakness, and then using a
brute-force approach involving LSB values, aka the 'Bar Mitzvah' issue.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/260001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.6, 8.0.0.11, 7.0.0.39 or later. Alternatively, upgrade to the minimal fix pack
level required by the interim fix and then apply Interim Fix PI34229.");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2808");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server");
  exit(0);
}

include('vcf.inc');

app = 'IBM HTTP Server';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

 if ('PI34229' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.5', 'fixed_display' : '8.5.5.6 or Interim Fix PI34229'},
  { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.10', 'fixed_display' : '8.0.0.11 or Interim Fix PI34229'},
  { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.37', 'fixed_display' : '7.0.0.39 or Interim Fix PI34229'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
