
##
# 
##



include('compat.inc');

if (description)
{
  script_id(151429);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2021-26035",
    "CVE-2021-26036",
    "CVE-2021-26037",
    "CVE-2021-26038",
    "CVE-2021-26039"
  );

  script_name(english:"Joomla 2.5.x < 3.9.28 Multiple Vulnerabilities (5840-joomla-3-9-28)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 2.5.x prior to
3.9.28. It is, therefore, affected by multiple vulnerabilities.

  - Inadequate escaping in the Rules field of the JForm API leads to a XSS vulnerability. (CVE-2021-26035)

  - Missing validation of input could lead to a broken usergroups table. (CVE-2021-26036)

  - Various CMS functions did not properly termine existing user sessions when a user's password was changed
    or the user was blocked. (CVE-2021-26037)

  - Install action in com_installer lack the required hardcoded ACL checks for superusers, leading to various
    potential attack vectors. A default system is not affected cause by default com_installer is limited to
    super users already. (CVE-2021-26038)

  - Inadequate escaping in the imagelist view of com_media leads to a XSS vulnerability. (CVE-2021-26039)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5840-joomla-3-9-28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff811b28");
  # https://developer.joomla.org/security-centre/856-20210701-core-xss-in-jform-rules-field.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc18b6c6");
  # https://developer.joomla.org/security-centre/857-20210702-core-dos-through-usergroup-table-manipulation.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea3ca23f");
  # https://developer.joomla.org/security-centre/858-20210703-core-lack-of-enforced-session-termination.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64f5301e");
  # https://developer.joomla.org/security-centre/859-20210704-core-privilege-escalation-through-com-installer.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b69b338");
  # https://developer.joomla.org/security-centre/860-20210705-core-xss-in-com-media-imagelist.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf612487");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.5.0', 'max_version' : '3.9.27', 'fixed_version' : '3.9.28' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
