#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125781);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id("CVE-2019-3598");
  script_bugtraq_id(107205);

  script_name(english:"McAfee Agent 5.0.x < 5.0.6 HF1267994 / 5.5.x < 5.5.1 HF1267991 / 5.6.x < 5.6.1 UDP DoS (SB10272)");
  script_summary(english:"Checks the McAfee Agent version.");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator
(ePO) Agent, installed on the remote host is 5.0.x prior to 5.0.6
HF1267994, 5.5.x prior to 5.5.1 HF1267991, or 5.6.x prior to 5.6.1.
It is, therefore, affected by a denial of service vulnerability. An
unauthenticated, remote attacker can exploit this issue, via
specifically crafted UDP packets, to cause the application  to stop
responding.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10272");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version  5.0.6 HF1267994, 5.5.1 HF1267991, 5.6.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3598");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed_nix.nbin", "mcafee_epo_agent_installed.nbin");
  exit(0);
}

include('vcf.inc');

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:3);

# Exact Build Numbers if needed:
#   https://kc.mcafee.com/corporate/index?page=content&id=KB51573
constraints = [
  { 'min_version' : '5.0', 'fixed_version' : '5.0.6.586', 'fixed_display' : '5.0.6 HF1267994' },
  { 'min_version' : '5.5', 'fixed_version' : '5.5.1.462', 'fixed_display' : '5.5.1 HF1267991' },
  { 'min_version' : '5.6', 'fixed_version' : '5.6.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
