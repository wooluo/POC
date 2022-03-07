
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123642);
  script_version("1.5");
  script_cvs_date("Date: 2019/08/22 16:57:38");

  script_cve_id(
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-0211",
    "CVE-2019-0215",
    "CVE-2019-0217",
    "CVE-2019-0220"
  );

  script_name(english:"Apache 2.4.x < 2.4.39 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.4.x prior to 2.4.39. It is, therefore, affected by multiple
vulnerabilities:

  - A privilege escalation vulnerability exists in
    module scripts due to an ability to execute arbitrary
    code as the parent process by manipulating the
    scoreboard. (CVE-2019-0211)

  - An access control bypass vulnerability exists in 
    mod_auth_digest due to a race condition when running
    in a threaded server. An attacker with valid credentials
    could authenticate using another username. (CVE-2019-0217)

  - An access control bypass vulnerability exists in 
    mod_ssl when using per-location client certificate
    verification with TLSv1.3. (CVE-2019-0215)

In addition, Apache httpd is also affected by several additional 
vulnerabilities including a denial of service, read-after-free
and URL path normalization inconsistencies. 

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://httpd.apache.org/security/vulnerabilities_24.html#2.4.39
  script_set_attribute(attribute:"see_also", value:"");
  # https://httpd.apache.org/security/vulnerabilities-httpd.xml
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.39 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0211");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/02");

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

# 2.4.39
constraints = [
  { 'min_version':'2.4', 'fixed_version':'2.4.39' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
