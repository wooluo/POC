
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152864);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2021-26084");
  script_xref(name:"IAVA", value:"2021-A-0397");

  script_name(english:"Atlassian Confluence < 6.13.23 / 6.14 < 7.4.11 / 7.5 < 7.11.6 / 7.12 < 7.12.5 Webwork OGNL Injection (CONFSERVER-67940)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an OGNL injection vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence application running on the remote host is 
prior to 6.13.23, 6.14.x prior to 7.4.11, 7.5.x prior to 7.11.6 or 7.12.x prior to 7.12.5. It is, therefore, affected by an OGNL injection
vulnerability that would allow an authenticated user, and in some instances an unauthenticated user, to execute
arbitrary code on a Confluence Server or Data Center instance.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://confluence.atlassian.com/doc/confluence-security-advisory-2021-08-25-1077906215.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb62fdb");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-67940");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.13.23, 7.4.11, 7.11.6, 7.12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26084");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'confluence', port:port, webapp:true);

var constraints = [
  {'fixed_version' : '6.13.23' },
  {'min_version' : '6.14', 'fixed_version' : '7.4.11' },
  {'min_version' : '7.5', 'fixed_version' : '7.11.6' },
  {'min_version' : '7.12', 'fixed_version' : '7.12.5', 'fixed_display' : '7.12.5 / 7.13.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
