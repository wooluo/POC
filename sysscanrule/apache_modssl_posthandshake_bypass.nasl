include("compat.inc");

if (description)
{
  script_id(51799017);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2019/04/03 17:45:32 $");

  script_cve_id("CVE-2019-0215");
  script_bugtraq_id(107667);

  script_name(english:"Apache mod_ssl Authentication Bypass Vulnerability(CVE-2019-0215)");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Apache HTTP Server is prone to a access-bypass vulnerability.

Successfully exploiting this issue may allow an attacker to bypass certain security restrictions and perform unauthorized actions.

Apache HTTP Server versions 2.4.38 and 2.4.37 are vulnerable; other versions may also be affected.  ");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2019-0215");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.39 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_attribute(attribute:"risk_factor", value: "High" );
  #script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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
include("ssl_funcs.inc");

ports = get_ssl_ports(fork:false, starttls:false);
if (isnull(ports) || max_index(ports) <= 0) exit(0, "There is no ssl ports.");

foreach port (ports)
{
  protos = get_kb_list("SSL/Transport/" + port);
  if (isnull(protos)) exit(0, "This no ssl transport protocols.");
  protos = make_list(protos);
  if (isnull(protos) || max_index(protos) <= 0) exit(0, "This no ssl transport protocols.");

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

  if (minver >= 37 && minver <= 38)
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
  }
  else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
}
