#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125635);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/31 14:59:40");

  script_cve_id("CVE-2019-0201");
  script_bugtraq_id(104253);
  script_xref(name:"IAVB", value:"2019-B-0041");

  script_name(english:"Apache ZooKeeper < 3.4.14 / 3.5.x < 3.5.5 Information Disclosure");
  script_summary(english:"Checks ZooKeeper version");

  script_set_attribute(attribute:"synopsis", value:"The remote Apache ZooKeeper server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ZooKeeper listening on the remote host is prior
to 3.4.14 or 3.5.x prior to 3.5.5. It is, therefore, affected by an information
disclosure vulnerability in ZooKeeper's getACL() command as a result of not
checking requester permissions. An unauthenticated, remote attacker can 
exploit this to disclose potentially sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/security.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/ZOOKEEPER-1392");
  script_set_attribute(attribute:"solution", value:
"Update to Apache ZooKeeper 3.4.14 or 3.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0201");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("apache_zookeeper_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/zookeeper", 2181);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");

port = get_service(svc:"zookeeper", default:2181, exit_on_fail:TRUE);
app_info = vcf::get_app_info(app:"Apache Zookeeper", port:port, service:TRUE);

# We can't check whether they're using digest auth or not via the config file
# or otherwise, so paranoid report. 
if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { "fixed_version" : "3.4.14"},
  { "min_version" : "3.5.0", "fixed_version" : "3.5.5" }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
