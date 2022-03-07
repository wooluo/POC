#
# (C) WebRAY Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(125923);
  script_version("1.4");
  script_cvs_date("Date: 2019/08/22 16:57:38");

  script_cve_id("CVE-2019-12764", "CVE-2019-12765", "CVE-2019-12766");
  script_bugtraq_id(108729, 108735, 108736);

  script_name(english:"Joomla 3.6.x < 3.9.7 Multiple Vulnerabilites");
  script_summary(english:"Checks the version of Joomla");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.6.x prior to
3.9.7. It is, therefore, affected by the following vulnerabilities:
  - Joomla versions 3.8.13 prior to 3.9.7 are affected by a vulnerability where a non-admin user may manipulate the 
    update server URL of the com_joomlaupdate component. An authenticated, remote attacker could exploit this to cause 
    an update to be pulled from a malicious server (CVE-2019-12764).

  - Joomla versions 3.9.x prior to 3.9.7 are affected by a CSV injection vulnerability due to insufficient validation 
    of user-supplied input. An unauthenticated, remote attacker may exploit this by submitting special characters to 
    the com_actionlogs component. When the resulting CSV file produced by Joomla is opened by a spreadsheet program 
    these special characters are interpretted as a formula (CVE-2019-12765).
  
  - Joomla versions 3.6.x prior to 3.9.6 are affected by a cross-site scripting (XSS) vulnerability due to improper 
    validation of user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit 
    this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser 
    session (CVE-2019-12766).

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5770-joomla-3-9-7-release.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.joomla.org/announcements/release-news/5771-joomla-3-9-8-release.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to Joomla! version 3.9.8 or later (Note: Joomla released
  security fixes for the above vulnerabilites in 3.9.7. However, this release introduced an additional bug so it is
  recommended to upgrade your installation to 3.9.8).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12765");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:80, php:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [
  { 'min_version' : '3.6.0', 'fixed_version' : '3.9.7', "fixed_display" : "3.9.7/3.9.8" }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
