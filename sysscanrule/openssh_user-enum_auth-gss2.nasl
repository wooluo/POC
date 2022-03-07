include("compat.inc");

if (description)
{
  script_id(51799019);
  script_version("1.6");
  script_cvs_date("Date: 2018/08/28 14:09:13");

  script_cve_id("CVE-2018-15919");
  script_bugtraq_id(101552);

  script_name(english:"OpenSSH auth-gss2 User Enumeration Vulnerability");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote OpenSSH is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Remotely observable behaviour in auth-gss2.c in OpenSSH through 7.8 could be used by remote attackers to detect existence of users on a target system when GSS2 is in use. NOTE: the discoverer states 'We understand that the OpenSSH developers do not want to treat such a username enumeration (or oracle) as a vulnerability.'");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2018/q3/180");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/bid/105163");
  script_set_attribute(attribute:"see_also", value:"https://security.netapp.com/advisory/ntap-20181221-0001/");

  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.8p1 later.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by WebRAY.");
  script_family(english:"Misc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/" + port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner)
  audit(AUDIT_NOT_LISTEN, "OpenSSH", port);
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);
if (backported)
  audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = pregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match))
  audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

fix = ">7.8p1 <5.9";
if (
  version =~ "^5\.9(p[0-9])?$" ||
  version =~ "^6\.[0-9](p[0-9])?$" ||
  version =~ "^7\.[0-7](p[0-9])?$" ||
  version =~ "^7\.8(p[0-1])?$"
   )
{
  items = make_array("Version source", banner,
                     "Installed version", version,
                     "Fixed version", fix);
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
