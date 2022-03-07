#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126639);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/12 13:46:09");

  script_cve_id("CVE-2019-1878");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvo28194");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190619-tele-shell-inj");
  script_xref(name:"IAVA", value:"2019-A-0220");

  script_name(english:"Cisco TelePresence Endpoint Command Shell Injection Vulnerability");
  script_summary(english:"Checks the version of Cisco TelePresence Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Codec (TC) and Collaboration Endpoint (CE) Cisco
TelePresence Software is affected by a vulnerability in the Cisco Discovery Protocol (CDP) implementation which could
allow an unauthenticated, adjacent attacker to inject arbitrary shell commands that are executed by the device. The
vulnerability is due to insufficient input validation of received CDP packets. An attacker could exploit this
vulnerability by sending crafted CDP packets to an affected device. A successful exploit could allow the attacker to
execute arbitrary shell commands or scripts on the targeted device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-tele-shell-inj
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo28194");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo28194");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1878");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:telepresence_ce");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = 'Cisco TelePresence TC/CE software';
device = get_kb_item_or_exit('Cisco/TelePresence_MCU/Device');
version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');

if (
  device !~ "^C\d" &&
  device !~ "^EX\d" &&
  device !~ "^MX\d" &&
  device !~ "^SX\d"
) audit(AUDIT_HOST_NOT, 'an affected Cisco TelePresence device');

short_version = pregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  short_type = short_version[1];
  short_num = short_version[2];
}

fix = '';

if (short_type == 'TC' && short_num =~ "^7\.")
  fix = '7.3.17';
else if (short_type == 'ce'){
  if (short_num =~ "^8\.")
    fix = '8.3.7';
  if (short_num =~ "^9\.[0-5]\.")
    fix = '9.5.3';
  if (short_num =~ "^9\.6\.")
    fix = '9.6.3';
}
else audit(AUDIT_NOT_DETECT, app_name);

if (!empty_or_null(fix) && ver_compare(ver:short_num, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : CSCvo28194' +
           '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
