#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127115);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/19 16:10:37");

  script_cve_id("CVE-2019-3619");
  script_bugtraq_id(109066);
  script_xref(name:"MCAFEE-SB", value:"SB10286");
  script_xref(name:"IAVA", value:"2019-A-0273");

  script_name(english:"McAfee ePolicy Orchestrator Insufficient Transport Layer Protection (SB10286)");
  script_summary(english:"Checks the installed version of ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by insufficient transport layer protection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee ePolicy Orchestrator that is affected by insufficient transport layer
protection. The ePO Agent Handler can incorrectly revert to plain text communication with the configured SQL server. A
remote, unauthenticated attacker could exploit this to view sensitives information by sniffing the communication
between the ePO Agent Handler and the SQL server.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10286");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ePO 5.9.1 HF1267793 / 5.10.0 Update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3619");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver", "Settings/ParanoidReport");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("vcf.inc");

app_name = "McAfee ePolicy Orchestrator";
kb_ver = "SMB/mcafee_epo/ver";

app_info = vcf::get_app_info(app:app_name, kb_ver:kb_ver);
app_info.path = get_kb_item_or_exit("SMB/mcafee_epo/Path");
win_port = get_kb_item("SMB/transport");
if (!win_port)
  app_info.port = 445;
else
  app_info.port = win_port;

# 5.9.1 and 5.10.0 both have fixes we can't detect
if ((app_info.version =~ "^5\.9\.1($|[^0-9])" || app_info.version =~ "^5\.10\.0($|[^0-9])") && report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  # 5.9.1 HF1267793
  {"fixed_version":"5.9.2", "fixed_display":"5.9.1 with HF1267793"},
  # 5.10.0 Update 4
  {"min_version":"5.10.0", "fixed_version":"5.10.1", "fixed_display":"5.10.0 with Update 4"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
