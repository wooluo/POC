#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124564);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/03 10:04:36");

  script_cve_id("CVE-2019-4061");
  script_bugtraq_id(107189);
  script_xref(name:"IAVB", value:"2019-B-0029");

  script_name(english:"IBM BigFix Platform 9.2.x <= 9.2.16 / 9.5.x <= 9.5.11 Information Disclosure");
  script_summary(english:"Checks the version of the IBM BigFix Server.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.2.x prior to 9.2.15, or
9.5.x prior to 9.5.10. It is, therefore, affected by an information
disclosure vulnerability in internet-facing relays if they are
configured as non-authenticating. A remote, unauthenticated attacker
could exploit this to disclose potentially sensitive information. 

IBM BigFix Platform was formerly known as Tivoli Endpoint Manager,
IBM Endpoint Manager, and IBM BigFix Endpoint Manager.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www-01.ibm.com/support/docview.wss?uid=ibm10870242
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor advisory (IBM Security Bulletin 870242) for suggested
workaround, or upgrade to an unaffected version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4061");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer","Settings/ParanoidReport");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("vcf.inc");
include("http.inc");

# since there is a workaround
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "IBM BigFix Server";
port = get_http_port(default:52311, embedded:FALSE);

kb_version = "www/BigFixHTTPServer/"+port+"/version";
version = get_kb_item_or_exit(kb_version);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app, port);

app_info = vcf::get_app_info(
  app:app,
  port:port,
  kb_ver:kb_version,
  service:TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "9.2", "max_version" : "9.2.16", "fixed_display":"Refer to vendor advisory." },
  { "min_version" : "9.5", "max_version" : "9.5.11", "fixed_display":"Refer to vendor advisory." }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
