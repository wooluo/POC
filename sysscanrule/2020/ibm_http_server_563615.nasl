##
# 
##

include('compat.inc');

if (description)
{
  script_id(144778);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/07");

  script_cve_id("CVE-2017-3167", "CVE-2017-7668", "CVE-2017-7679");
  script_bugtraq_id(99135, 99137, 99170);

  script_name(english:"IBM HTTP Server 7.0.0.0 < 7.0.0.45 / 8.0.0.0 < 8.0.0.14 / 8.5.0.0 < 8.5.5.12 / 9.0.0.0 < 9.0.0.5 Multiple Vulnerabilities (563615)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by multiple vulnerabilities related to Apache
HTTP Server, as follows:

  - In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a
    buffer when sending a malicious Content-Type response header. (CVE-2017-7679)

  - The HTTP strict parsing changes added in Apache httpd 2.2.32 and 2.4.24 introduced a bug in token list
    parsing, which allows ap_find_token() to search past the end of its input string. By maliciously crafting
    a sequence of request headers, an attacker may be able to cause a segmentation fault, or to force
    ap_find_token() to return an incorrect value. (CVE-2017-7668)

  - In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_get_basic_auth_pw() by
    third-party modules outside of the authentication phase may lead to authentication requirements being
    bypassed. (CVE-2017-3167)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/563615");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.45, 8.0.0.14, 8.5.5.12, 9.0.0.5, or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply Interim Fix PI82481.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7679");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server");

  exit(0);
}


include('vcf.inc');

app = 'IBM HTTP Server';
fix = 'Interim Fix PI82481';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI82481' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.43', 'fixed_display' : '7.0.0.45 or ' + fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.13', 'fixed_display' : '8.0.0.14 or ' + fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.11', 'fixed_display' : '8.5.5.12 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.4', 'fixed_display' : '9.0.0.5 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
