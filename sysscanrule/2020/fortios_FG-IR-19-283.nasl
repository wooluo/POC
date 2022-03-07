#TRUSTED 781a916a9e3fdc8a567c449eb41a94ff07813b495fa03f056ac1957cbf0306c779eca6217f2057ceebdaae27745bf6e0967b565f7698082fc858256036a184bb418c921dbcfef74f8e5a244e8e5c4e2e26c6b3dd7543f84af8e06a339c20ed6be9e004ff7486dea7e6b009e7fe2fbb2d88a374eec3bdf17e14715b4995d358ecf7d5acc246669616cdf1f5495e8b4ded85fe170c828dfc4d3bca2b3fe60f2e98d3dc066351080e4c9dad5a26d43a48e80af88a920506d7ded222825cabf417683fd566204e22aa88d292d83ea114f45e450276b57e3efd4904ad068974e7b2b84b173505b7ba6c8de253086c8e33656c4a4e1ea4dcf3e32d2aa11da6535a4f2a6defe01379ab4b18b7ef64d17f217b2ffec24f0aa3c0bca32ba5fa20968d71ac221c1cd43a5ac5d383e7e3efddc1cf5966f0b5581572d167c0d25608da1694eb42cc8847f8a1e758d50456c299f9e3be18da1b7665551b41f5ed9eabe7298ca8ddaacf5498529d341e23f293c6ac6126dd2b95cc1b589d5817b1d918230e69cfcf5c184dc694b4526c859923198929b8bb8e3b50646cb2ff7ee848d05c0ed569b8fbd1033949ddf71831225dbd49cb38f6e0146a767647e21b184be754256b39a2b306a154a5c617699265289233aa49d3ba4a1050dca9f0047396e7c5695e36de759a0ad0080ca0d502f755c84802410bf574593a8bdc019b877cb0d1e1a981
#
# 
#

include('compat.inc');

if (description)
{
  script_id(141122);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/05");

  script_cve_id("CVE-2020-12812");
  script_xref(name:"IAVA", value:"2020-A-0440");

  script_name(english:"Fortinet FortiOS < 6.0.10 / 6.2.x < 6.2.4 / 6.4.x < 6.4.1 Improper Authentication (FG-IR-19-283)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 6.0.10, 6.2.x prior to 6.2.4, or 6.4.x prior to 6.4.1. It is,
therefore, affected by an improper authentication vulnerability due to an issue with the 'username-case-sensitivity' CLI
attribute for the SSL VPN. An unauthenticated, remote attacker can exploit this, by changing the case of the username,
to log in without being prompted for FortiToken 2FA.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-19-283");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.0.10, 6.2.4, 6.4.1 or later, or apply the workaround from the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12812");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('ssh_func.inc');
include('hostlevel_funcs.inc');

version = get_kb_item_or_exit('Host/Fortigate/version');
appname = get_kb_item_or_exit('Host/Fortigate/model');

port = 0;

fix = '6.0.10';
if (version =~ "^6\.2\.") 
  fix = '6.2.4';
else if (version =~ "^6\.4\.")
  fix = '6.4.1';

report = '';

if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);
}

buf = get_kb_item('Secret/Host/Fortigate/full-configuration_user_local');
if (empty_or_null(buf))
{
  if ( islocalhost() )
  {
    if ( ! defined_func('pread')  ) audit(AUDIT_FN_UNDEF, 'pread');
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (! sock_g) audit(AUDIT_SOCK_FAIL, port, 'SSH');
    info_t = INFO_SSH;
  }

  buf = ssh_cmd(cmd:'show full-configuration user local', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
  ssh_close_connection();
  if (!empty_or_null(buf))
    set_kb_item(name:'Secret/Host/Fortigate/full-configuration_user_local', value:buf);
}
if ('config user local' >!< buf)
{ 
  report +=
  '\n' +
  '  Nessus could not confirm fortiguard system config\n' +
  '  Please ensure the policy settings are correct,\n' +
  '  Including the new "Automatically accept detected SSH disclaimer prompts"';
}
else if ('username-case-sensitivity enable' >!< buf)
{
  audit(AUDIT_OS_CONF_NOT_VULN, appname, version);
}

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
