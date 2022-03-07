##
# 
##


include('compat.inc');

if (description)
{
  script_id(149899);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2021-26032", "CVE-2021-26033", "CVE-2021-26034");

  script_name(english:"Joomla 3.0.x < 3.9.27 Multiple Vulnerabilities (5836-joomla-3-9-27)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.0.x prior to
3.9.27. It is, therefore, affected by multiple vulnerabilities.

  - HTML was missing in the executable block list of MediaHelper::canUpload, leading to XSS attack vectors.
    (CVE-2021-26032)

  - A missing token check causes a CSRF vulnerability in the AJAX reordering endpoint. (CVE-2021-26033)

  - A missing token check causes a CSRF vulnerability in data download endpoints in com_banners and
    com_sysinfo. (CVE-2021-26034)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5836-joomla-3-9-27.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff41b521");
  # https://developer.joomla.org/security-centre/852-20210501-core-adding-html-to-the-executable-block-list-of-mediahelper-canupload.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d371fc9");
  # https://developer.joomla.org/security-centre/853-20210502-core-csrf-in-ajax-reordering-endpoint.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a2f0bcb");
  # https://developer.joomla.org/security-centre/854-20210503-core-csrf-in-data-download-endpoints.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2875139a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

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
  { 'min_version' : '3.0.0', 'max_version' : '3.9.26', 'fixed_version' : '3.9.27' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
