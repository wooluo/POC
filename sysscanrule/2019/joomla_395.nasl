#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(123954);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/24 15:26:42");

  script_cve_id("CVE-2019-10945", "CVE-2019-10946");

  script_name(english:"Joomla! 1.5.0 < 3.9.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla! installation running on the remote web server is 1.5.0 or
later but prior to 3.9.5. It is, therefore, affected by multiple vulnerabilities:

  - A directory traversal vulnerability exists in versions 1.5.0 to 3.9.4 within the Media Manager component 
    due to improperly sanitizing the folder parameter. An authenticated, remote attacker can exploit this, by
    sending a URI that contains directory traversal characters, to disclose the contents of files located
    outside of the server's restricted path. (CVE-2019-10945)

  - An access control limit bypass exists in versions 3.2.0 to 3.9.4 within the gethelpsites() function of the
    com_users component. An unauthenticated, remote attacker can exploit this and access the 'refresh list of
    helpsites' endpoint. (CVE-2019-10946)

 - A cross-site scripting (XSS) vulnerability exists in versions 3.0.0 to 3.9.4 due to improper validation of
   user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit this, by
   convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser
   session.


Note that GizaNE has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5764-joomla-3-9-5-release.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10946");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:80, php:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"Joomla!", port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "1.5.0", "fixed_version" : "3.9.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags: {xss:true});
