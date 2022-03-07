#
# 
#

include("compat.inc");

if (description)
{
  script_id(101025);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/06/27 13:28:15 $");

  script_name(english:"Elasticsearch Unrestricted Access Information Disclosure");
  script_summary(english:"Detects unprotected elasticsearch instances.");

  script_set_attribute(attribute:"synopsis", value:
"The search engine running on the remote web server is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Elasticsearch application running on the remote web server is
affected by an information disclosure vulnerability due to a failure
to restrict resources via authentication. An unauthenticated, remote
attacker can exploit this to disclose sensitive information from the
database.");
  # https://threatpost.com/insecure-backend-databases-blamed-for-leaking-43tb-of-app-data/126021/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d055e692");
  # https://www.elastic.co/guide/en/x-pack/current/setting-up-authentication.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b80612a1");
  script_set_attribute(attribute:"solution", value:
"Enable native user authentication or integrate with an external user
management system such as LDAP and Active Directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");


  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("elasticsearch_detect.nbin");
  script_require_keys("installed_sw/Elasticsearch");
  script_require_ports("Services/www",9200);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "Elasticsearch";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9200);

install = get_single_install(app_name:app, port:port);

dir  = install['path'];
url  = build_url(qs:dir, port:port);

# Get list of indices
res = http_send_recv3(
  method:"GET",
  item:"/_cat/indices",
  port:port,
  exit_on_fail:FALSE
);

# protected
if ("200 OK" >!< res[0])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

indices = "";
foreach line (split(res[2]))
{
  fields = split(line, sep:" ");
  indices += fields[2] + '\n';
}

if (empty(indices))
  extra = 'Nessus detected an unprotected instance of Elasticsearch with no indices.';
else
  extra = 'Nessus detected an unprotected instance of Elasticsearch with the following indices :' +
          '\n\n'+http_last_sent_request()+ '\n\n' +indices;

security_report_v4(
  port: port,
  severity: SECURITY_WARNING,
  extra: extra
);
