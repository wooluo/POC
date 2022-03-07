##
# 
##

include('compat.inc');

if (description)
{
  script_id(147705);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/18");

  script_cve_id(
    "CVE-2021-23126",
    "CVE-2021-23127",
    "CVE-2021-23128",
    "CVE-2021-23129",
    "CVE-2021-23130",
    "CVE-2021-23131",
    "CVE-2021-23132",
    "CVE-2021-26027",
    "CVE-2021-26028",
    "CVE-2021-26029"
  );
  script_xref(name:"IAVA", value:"2021-A-0119");

  script_name(english:"Joomla 1.6.x < 3.9.25 Multiple Vulnerabilities (5834-joomla-3-9-25)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 1.6.x prior to
3.9.25. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in Joomla! 3.2.0 through 3.9.24. Usage of the insecure rand() function within
    the process of generating the 2FA secret. (CVE-2021-23126)

  - An issue was discovered in Joomla! 3.2.0 through 3.9.24. Usage of an insufficient length for the 2FA
    secret accoring to RFC 4226 of 10 bytes vs 20 bytes. (CVE-2021-23127)

  - An issue was discovered in Joomla! 3.2.0 through 3.9.24. The core shipped but unused randval implementation
    within FOF (FOFEncryptRandval) used an potential insecure implemetation. That has now been replaced with a
    call to 'random_bytes()' and its backport that is shipped within random_compat. (CVE-2021-23128)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5834-joomla-3-9-25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38f83c52");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '1.6.0', 'max_version' : '3.9.24', 'fixed_version' : '3.9.25' }
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
