include("compat.inc");

if (description)
{
  script_id(51799015);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2019/04/03 17:45:32 $");

  script_cve_id("CVE-2019-0211");
  script_bugtraq_id(107666);

  script_name(english:"Apache Root Privilege Escalation(CVE-2019-0211)");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker or prefork, code executing in less-privileged child processes or threads (including scripts executed by an in-process scripting interpreter) could execute arbitrary code with the privileges of the parent process (usually root) by manipulating the scoreboard. ");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2019-0211");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.39 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_attribute(attribute:"risk_factor", value: "High" );
  #script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 WebRAY, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache web server");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

version = eregmatch(pattern:"^2\.4\.\d+", string:version);
if (isnull(version)) audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version[0]);
version = version[0];

minver = eregmatch(pattern:"^2.4.(\d+)$", string:version);
if (isnull(minver)) audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
minver = minver[1];

if (minver >= 17 && minver <= 38)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
