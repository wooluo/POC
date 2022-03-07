#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(124281);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/26 11:34:29");

  script_cve_id("CVE-2019-3398");
  script_xref(name:"IAVA", value:"2019-A-0135");

  script_name(english:"Atlassian Confluence < 6.6.13 / 6.7.x < 6.12.4 / 6.13.x < 6.13.4 / 6.14.x < 6.14.3 / 6.15.x < 6.15.2 Directory Traversal Vulnerability");
  script_summary(english:"Checks the Atlassian Confluence version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a directory traversal vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence application running on the remote host is prior
to 6.6.13, 6.7.x prior to 6.12.4, 6.13.x prior to 6.13.4, 6.14.x prior to 6.14.3 or 6.15.x prior to 6.15.2. It is, 
therefore, affected by a directory traversal vulnerability which exists in download all attachments component. An 
authenticated, remote attacker can exploit this, by sending a URI that contains directory traversal characters, 
to write files to arbitrary locations which may lead to remote code execution. 

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/doc/confluence-security-advisory-2019-04-17-968660855.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.6.13, 6.12.4, 6.13.4, 6.14.3, 6.15.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3398");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_ports("Services/www", 8080, 8090);
  script_require_keys("installed_sw/confluence", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "confluence";

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, port:port, webapp:true);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {                         "fixed_version": "6.6.13", "fixed_display": "6.6.13 / 6.15.2" },
  {"min_version": "6.7.0",  "fixed_version": "6.12.4", "fixed_display": "6.12.4 / 6.15.2" },
  {"min_version": "6.13.0", "fixed_version": "6.13.4", "fixed_display": "6.13.4 / 6.15.2" },
  {"min_version": "6.14.0", "fixed_version": "6.14.3", "fixed_display": "6.14.3 / 6.15.2" },
  {"min_version": "6.15.0", "fixed_version": "6.15.2", "fixed_display": "6.15.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
