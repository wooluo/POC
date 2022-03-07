#
# 
#


include('compat.inc');

if (description)
{
  script_id(149260);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id(
    "CVE-2020-28007",
    "CVE-2020-28008",
    "CVE-2020-28009",
    "CVE-2020-28010",
    "CVE-2020-28011",
    "CVE-2020-28012",
    "CVE-2020-28013",
    "CVE-2020-28014",
    "CVE-2020-28015",
    "CVE-2020-28016",
    "CVE-2020-28017",
    "CVE-2020-28018",
    "CVE-2020-28019",
    "CVE-2020-28020",
    "CVE-2020-28021",
    "CVE-2020-28022",
    "CVE-2020-28023",
    "CVE-2020-28024",
    "CVE-2020-28025",
    "CVE-2020-28026",
    "CVE-2021-27216"
  );
  script_xref(name:"IAVA", value:"2021-A-0216");

  script_name(english:"Exim < 4.94.2 Multiple Vulnerabilities (21Nails)");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote host is prior to 4.94.2. It is, therefore,
potentially affected by multiple vulnerabilities that can lead to remote code execution.");
  # https://blog.qualys.com/vulnerabilities-research/2021/05/04/21nails-multiple-vulnerabilities-in-exim-mail-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5800058f");
  script_set_attribute(attribute:"see_also", value:"https://www.qualys.com/2021/05/04/21nails/21nails.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.exim.org/static/doc/security/CVE-2020-qualys/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.94.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

var banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("Exim" >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);

var matches = pregmatch(pattern:"220.*Exim ([0-9\._]+)", string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

var version = matches[1];
# Underscore was added to the vesion
version = ereg_replace(string:version, pattern:'_', replace:'.');

if (ver_compare(ver:version, fix:'4.94.2', strict:FALSE) < 0)
{
  report =
    '\n  Banner            : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.94.2';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
