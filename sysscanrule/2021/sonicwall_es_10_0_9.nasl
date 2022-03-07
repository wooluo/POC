##
# 
##

include('compat.inc');

if (description)
{
  script_id(149047);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2021-20021", "CVE-2021-20022", "CVE-2021-20023");

  script_name(english:"SonicWall Email Security 10.0.x < 10.0.9.6173 / 6177 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall Email Security is affected by multiple vulnerabilities:

  - A vulnerability in the SonicWall Email Security version 10.0.9.x allows an attacker to create an administrative 
    account by sending a crafted HTTP request to the remote host. (CVE-2021-20021)

  - SonicWall Email Security version 10.0.9.x contains a vulnerability that allows a post-authenticated attacker to upload 
    an arbitrary file to the remote host. (CVE-2021-20022)

  - SonicWall Email Security version 10.0.9.x contains a vulnerability that allows a post-authenticated attacker to read 
    an arbitrary file on the remote host. (CVE-2021-20023)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.sonicwall.com/support/product-notification/security-notice-sonicwall-email-security-zero-day-vulnerabilities/210416112932360/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?218b685b");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b68bb26e");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7c24e3d");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0009
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aab2b0d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.0.9.6173 or later for Windows, or 10.0.9.6177 or later for Appliance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20021");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonicwall:email_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_email_security_detect.nbin");
  script_require_keys("installed_sw/SonicWall Email Security");

  exit(0);
}

include('vcf.inc');
include('http.inc');

app_name = 'SonicWall Email Security';
port = get_http_port(default:443,embedded:TRUE);
app = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);

# fixed version depends on windows / appliance flavour
# customising fixed_display as well to emphasize affected flavour and avoid confusion
if ('Windows' >< app['Model'])
{
  fixed_version = '10.0.9.6173';
  fixed_display = 'SonicWall ES (Windows) version ' + fixed_version + ' or later.';
}
else
{
  fixed_version = '10.0.9.6177';
  fixed_display = 'SonicWall ES (Appliance) version ' + fixed_version + ' or later.';
}

constraints =
[
  {'min_version' : '10.0.1', 'fixed_version' : fixed_version, 'fixed_display':fixed_display}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
