#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126826);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19 15:42:32");

  script_cve_id("CVE-2019-6328", "CVE-2019-6329");
  script_bugtraq_id(108891);
  script_xref(name:"HP", value:"c06388027");
  script_xref(name:"HP", value:"HPSBGN03620");
  script_xref(name:"IAVB", value:"2019-B-0061");

  script_name(english:"HP Support Assistant < 8.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Support Assistant.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
two privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Support Assistant installed on the remote Windows
host is prior to 8.8. It is, therefore, affected by two unspecified
privilege escalation vulnerabilities. An authenticated, local attacker
can exploit this, to gain system level access to the system.");
  # https://support.hp.com/ca-en/document/c06388027
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Support Assistant version 8.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6328");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:support_assistant");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("hp_support_assistant_installed.nbin");
  script_require_keys("installed_sw/HP Support Assistant");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'HP Support Assistant');
constraints = [{ 'fixed_version' : '8.8' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
