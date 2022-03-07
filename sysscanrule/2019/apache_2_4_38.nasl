
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121355);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 15:17:20");

  script_cve_id(
    "CVE-2018-17189",
    "CVE-2018-17199",
    "CVE-2019-0190"
  );

  script_name(english:"Apache 2.4.x < 2.4.38 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.4.x prior to 2.4.38. It is, therefore, affected by multiple
vulnerabilities:

  - A denial of service (DoS) vulnerability exists in HTTP/2 steam
    handling. An unauthenticated, remote attacker can exploit this
    issue, via sending request bodies in a slow loris way to plain
    resources, to occupy a server thread. (CVE-2018-17189)

  - A vulnerability exists in mod_sesion_cookie, as it does not
    properly check the expiry time of cookies. (CVE-2018-17199) 

  - A denial of service (DoS) vulnerability exists in mod_ssl when
    used with OpenSSL 1.1.1 due to an interaction in changes to
    handling of renegotiation attempts. An unauthenticated, remote
    attacker can exploit this issue to cause mod_ssl to stop
    responding. (CVE-2019-0190)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.38");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.38");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0190");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:80);
kb_base = "www/apache/"+port+"/";
kb_ver = NULL;
kb_backport = NULL;
kb_source = NULL;

if (get_kb_item(kb_base+"version")) kb_ver = kb_base+"version";
if (get_kb_item(kb_base+"backported")) kb_backport = kb_base+"backported";
if (get_kb_item(kb_base+"source")) kb_source = kb_base+"source";

app_info = vcf::get_app_info(
  app:"Apache",
  port:port,
  kb_ver:kb_ver,
  kb_backport:kb_backport,
  kb_source:kb_source,
  service:TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

# 2.4.38
constraints = [
  { "min_version":"2.4", "fixed_version":"2.4.38" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
