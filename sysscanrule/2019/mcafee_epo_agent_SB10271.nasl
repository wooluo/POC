#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125780);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id("CVE-2019-3599");
  script_bugtraq_id(107202);

  script_name(english:"McAfee Agent < 5.6.1 Information Disclosure Vulnerability (SB10271)");
  script_summary(english:"Checks the McAfee Agent version.");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator
(ePO) Agent, installed on the remote host is 5.0.x, 5.5.x, or 5.6.x
< 5.6.1. It is, therefore, affected by an information disclosure
vulnerability. An unauthenticated, remote attacker can exploit this,
via the remote logger, to disclose potentially sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10271");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.6.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3599");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/26");
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
  { 'min_version' : '5.0', 'max_version' : '5.5.4', 'fixed_version' : '5.6.1' },
  { 'min_version' : '5.6', 'fixed_version' : '5.6.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
