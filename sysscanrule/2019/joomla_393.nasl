#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122346);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/15 15:35:01");

  script_cve_id(
    "CVE-2019-7739",
    "CVE-2019-7740",
    "CVE-2019-7741",
    "CVE-2019-7743",
    "CVE-2019-7744"
  );
  script_bugtraq_id(
    107015,
    107017,
    107018,
    107020,
    107050
  );

  script_name(english:"Joomla! 2.5.0 < 3.9.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is prior to 3.9.3. 
It is, therefore, affected by multiple vulnerabilities:

 - An object injection vulnerability exists in Joomla! prior to 3.9.3
  due to the absence of a protection mechanism to prevent the use of 
  the phar:// handler for non .phar files. An unauthenticated, remote 
  attacker can exploit this to include arbitrary files (CVE-2019-7743).

 - A cross-site scripting (XSS) vulnerability exists due to improper 
 validation of user-supplied input before returning it to users. 
 An unauthenticated, remote attacker can exploit this, by convincing
 a user to click a specially crafted URL, to execute arbitrary script
 code in a user's browser session (CVE-2019-7740, CVE-2019-7741, 
 CVE-2019-7744).

 - An issue exists in Joomla! prior to 3.9.3. The 'No Filtering' 
  textfilter overrides child settings in the Global Configuration.
  This is intended behavior. However, it might be unexpected for 
  the user because the configuration dialog lacks an additional 
  message to explain this (CVE-2019-7739).

Note that GizaNE has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5756-joomla-3-9-3-release.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7743");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/20");

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

include("http.inc");
include("vcf.inc");

port = get_http_port(default:80, php:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"Joomla!", port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.5.0", "fixed_version" : "3.9.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
