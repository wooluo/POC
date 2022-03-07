#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123756);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/05  8:09:50");

  script_cve_id("CVE-2019-0222");
  script_bugtraq_id(107622);
  script_xref(name:"IAVB", value:"2019-B-0023");

  script_name(english:"Apache ActiveMQ 5.x < 5.15.9 Corrupt MQTT Frame Denial of Service (DoS) (CVE-2019-0222)");
  script_summary(english:"Checks the version of ActiveMQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x
prior to 5.15.9. It is, therefore, affected by a denial of service
(DoS) vulnerability due to improper validation of MQTT frames. An
unauthenticated, remote attacker can exploit this issue to cause the
broker to stop responding.");
  # http://activemq.apache.org/security-advisories.data/CVE-2019-0222-announcement.txt
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.15.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0222");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'ActiveMQ';
port = get_http_port(default:8161);
app = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

constraints = [{"min_version" : "5.0", "fixed_version" : "5.15.9"}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
