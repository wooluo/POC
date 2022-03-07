#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122777);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/15 15:35:01");

  script_cve_id("CVE-2019-8936");
  script_bugtraq_id(107337);
  script_xref(name:"IAVA", value:"2019-A-0078");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p13 / 4.3.x < 4.3.94 DoS");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p13, or is
4.3.x prior to 4.3.94. It is, therefore, affected by a denial of
service vulnerability due to a flaw in handling authenticated mode 6
traffic. An authenticated attacker can exploit this issue to cause
application crashes.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#March_2019_ntp_4_2_8p13_NTP_Rele
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3565");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p13, 4.3.94 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:M/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8936");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Paranoia check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

app_name = "NTP Server";

port = get_kb_item("Services/udp/ntp");
if (empty_or_null(port)) port = 123;

version = get_kb_item_or_exit("Services/ntp/version");
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, app_name);

match = pregmatch(string:version, pattern:"([0-9]+\.[0-9]+\.[0-9p]+)");
if (empty_or_null(match)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

ver = match[1];
verfields = split(ver, sep:".", keep:FALSE);
major = int(verfields[0]);
minor = int(verfields[1]);
if ('p' >< verfields[2])
{
  revpatch = split(verfields[2], sep:"p", keep:FALSE);
  rev = int(revpatch[0]);
  patch = int(revpatch[1]);
}
else
{
  rev = verfields[2];
  patch = 0;
}

# This vulnerability affects NTP 4.x < 4.2.8p13
# Check for vuln, else audit out.
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 13)
)
{
  fix = "4.2.8p13";
}
else if (major == 4 && minor == 3 && rev < 94)
{
  fix = "4.3.94";
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(
  port  : port,
  proto : "udp",
  extra : report,
  severity : SECURITY_WARNING
);
exit(0);
