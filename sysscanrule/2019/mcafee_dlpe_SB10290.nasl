#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127117);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/05  5:20:46");

  script_cve_id(
    "CVE-2019-3591",
    "CVE-2019-3595",
    "CVE-2019-3621",
    "CVE-2019-3622"
  );
  script_bugtraq_id(
    109370,
    109377
  );
  script_xref(name:"MCAFEE-SB", value:"SB10289");
  script_xref(name:"MCAFEE-SB", value:"SB10290");
  script_xref(name:"IAVA", value:"2019-A-0268");

  script_name(english:"McAfee DLPe Agent < 11.1.200 / 11.2.x Multiple Vulnerabilities (SB10289) (SB10290)");
  script_summary(english:"Checks the version of McAfee DLPe.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a master bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Data Loss Prevention Endpoint (DLPe) Agent installed on the remote Windows host is prior to
11.1.200 or 11.2.x. It is, therefore, affected by multiple vulnerabilities:

  - Stored XSS in the ePO extension UI. (CVE-2019-3591)

  - Authenticated command injection in the ePO extension. (CVE-2019-3595)

  - Physical access authentication bypass. (CVE-2019-3621)

  - Arbitrary log file redirect. (CVE-2019-3622)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10289");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10290");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee DLPe 11.1.200 or 11.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3622");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"McAfee DLPe Agent", win_local:TRUE);

constraints = [
  { "fixed_version":"11.1.200" },
  { "min_version":"11.2", "fixed_version":"11.3.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
