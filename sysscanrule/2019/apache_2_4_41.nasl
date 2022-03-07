#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128033);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/22 16:57:38");

  script_cve_id(
    "CVE-2019-9517",
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10092",
    "CVE-2019-10097",
    "CVE-2019-10098"
  );
  script_xref(name:"IAVA", value:"2019-A-0302");

  script_name(english:"Apache 2.4.x < 2.4.41 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.41. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.41 advisory.

  - HTTP/2 (2.4.20 through 2.4.39) very early pushes, for
    example configured with H2PushResource, could lead to
    an overwrite of memory in the pushing request's pool,
    leading to crashes. The memory copied is that of the
    configured push link header values, not data supplied by
    the client. (CVE-2019-10081)

  - Some HTTP/2 implementations are vulnerable to
    unconstrained interal data buffering, potentially
    leading to a denial of service. The attacker opens the
    HTTP/2 window so the peer can send without constraint;
    however, they leave the TCP window closed so the peer
    cannot actually write (many of) the bytes on the wire.
    The attacker then sends a stream of requests for a large
    response object. Depending on how the servers queue the
    responses, this can consume excess memory, CPU, or both.
    (CVE-2019-9517)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10097");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:80);
kb_base = 'www/apache/'+port+'/';
kb_ver = NULL;
kb_backport = NULL;
kb_source = NULL;

if (get_kb_item(kb_base+'version')) kb_ver = kb_base+'version';
if (get_kb_item(kb_base+'backported')) kb_backport = kb_base+'backported';
if (get_kb_item(kb_base+'source')) kb_source = kb_base+'source';

app_info = vcf::get_app_info(
  app:'Apache',
  port:port,
  kb_ver:kb_ver,
  kb_backport:kb_backport,
  kb_source:kb_source,
  service:TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.4.0', 'fixed_version' : '2.4.41' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
