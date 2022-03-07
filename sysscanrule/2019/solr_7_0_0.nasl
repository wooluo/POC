#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123417);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/27 13:35:21");

  script_cve_id("CVE-2019-0192");
  script_bugtraq_id(107318);

  script_name(english:"Apache Solr 5.x <= 5.5.5 or 6.x <= 6.6.5 Deserialization Vulnerability");
  script_summary(english:"Checks version of Solr");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote web server is affected by a remote code execution vulnerability in the
Config API due to unsafe deserialization of Java objects. An unauthenticated, remote attacker can exploit this, via an
HTTP POST request that points the JMX server to a  malicious RMI server. An attacker could then send a crafted
serialized Java object to the server, to execute arbitrary code.
");
  # http://mail-archives.us.apache.org/mod_mbox/www-announce/201903.mbox/%3CCAECwjAV1buZwg%2BMcV9EAQ19MeAWztPVJYD4zGK8kQdADFYij1w%40mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 7.0 or later, refer to the vendor advisory for relevant patch and configuration
settings.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0192");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_dependencies("solr_detect.nbin");
  script_require_keys("installed_sw/Apache Solr", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8983);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Apache Solr';
get_install_count(app_name:app,exit_if_zero:TRUE);
port = get_http_port(default:8983);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [{'min_version' : '5.0.0', 'max_version' : '5.5.5', 'fixed_version' : '7.0'},
               {'min_version' : '6.0.0', 'max_version' : '6.6.5', 'fixed_version' : '7.0'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
