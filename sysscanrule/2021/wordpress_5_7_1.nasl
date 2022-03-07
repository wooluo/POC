##
# 
##

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-7-1-security-and-maintenance-release.

include('compat.inc');

if (description)
{
  script_id(148844);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2021-29447", "CVE-2021-29450");

  script_name(english:"WordPress 5.7 < 5.7.1 / 5.6 < 5.6.3 / 5.5 < 5.5.4 / 5.4 < 5.4.5 / 5.3 < 5.3.7 / 5.2 < 5.2.10 / 5.1 < 5.1.9 / 5.0 < 5.0.12 / 4.9 < 4.9.17 / 4.8 < 4.8.16 / 4.7 < 4.7.20");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"WordPress 5.7 < 5.7.1 / 5.6 < 5.6.3 / 5.5 < 5.5.4 / 5.4 < 5.4.5 / 5.3 < 5.3.7 / 5.2 < 5.2.10 / 5.1 < 5.1.9 / 5.0 <
5.0.12 / 4.9 < 4.9.17 / 4.8 < 4.8.16 / 4.7 < 4.7.20 is affected by multiple vulnerabilities:

  - A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library
    leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is
    possible in a successful XXE attack. (CVE-2021-29447)

  - One of the blocks in the WordPress editor can be exploited in a way that exposes password-protected posts and
    pages. This requires at least contributor privileges. (CVE-2021-29450)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00aa3f86");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-7-1/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/download/releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.7.1, 5.6.3, 5.5.4, 5.4.5, 5.3.7, 5.2.10, 5.1.9, 5.0.12, 4.9.17, 4.8.16, 4.7.10, or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29447");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

constraints = [
  {'min_version':'4.7','fixed_version':'4.7.20'},
  {'min_version':'4.8','fixed_version':'4.8.16'},
  {'min_version':'4.9','fixed_version':'4.9.17'},
  {'min_version':'5.0','fixed_version':'5.0.12'},
  {'min_version':'5.1','fixed_version':'5.1.9'},
  {'min_version':'5.2','fixed_version':'5.2.10'},
  {'min_version':'5.3','fixed_version':'5.3.7'},
  {'min_version':'5.4','fixed_version':'5.4.5'},
  {'min_version':'5.5','fixed_version':'5.5.4'},
  {'min_version':'5.6','fixed_version':'5.6.3'},
  {'min_version':'5.7','fixed_version':'5.7.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
