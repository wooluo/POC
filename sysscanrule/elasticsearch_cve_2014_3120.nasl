include("compat.inc");

if (description)
{
  script_id(51799009);
  script_version("1.3");
  script_cvs_date("Date: 2014/12/15 15:21:06");

  script_cve_id("CVE-2014-3120");
  script_bugtraq_id(67731);

  script_name(english:"Elasticsearch Remote Code Execution(CVE-2014-3120)");
  script_summary(english:"Checks the installed Elasticsearch version");

  script_set_attribute(attribute:"synopsis", value:
"The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.");
  script_set_attribute(attribute:"description", value:
"he default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search. NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.");
  #https://discuss.elastic.co/t/elasticsearch-remote-code-execution-cve-2015-5377/25736
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2014-3120");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to 1.2.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_dependencies("elasticsearch_detect.nbin");
  script_require_keys("installed_sw/Elasticsearch");
  script_require_ports("Services/www",9200);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "Elasticsearch";

get_install_count(app_name:app, exit_if_zero:TRUE);

#port = get_http_port(default:9200);
port = 9200;

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

#display(app_info);

constraints = [
  { "min_version" : "0.0.0", "fixed_version" : "1.2.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
