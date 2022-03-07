#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126338);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/28 12:13:30");

  script_cve_id("CVE-2019-11582");
  script_bugtraq_id(108797);
  script_xref(name:"IAVA", value:"2019-A-0213");

  script_name(english:"Atlassian SourceTree 0.5a < 3.1.3 Remote Code Execution vulnerability");
  script_summary(english:"Checks the version of Atlassian SourceTree.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian SourceTree installed on the remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian SourceTree installed on the remote Windows host is version 0.5a prior to 3.1.3. It is, 
therefore, affected by a remote code execution vulnerability in the URI handling component. An unauthenticated, remote
attacker could exploit this, via sending a malicious URL to a victim to execute arbitrary commands.
");
  # https://confluence.atlassian.com/sourcetreekb/sourcetree-security-advisory-2019-06-05-972329885.html?_ga=2.34980129.1864440785.1560967908-766934728.1537300451
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian SourceTree 3.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11582");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:sourcetree");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I"); 
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_sourcetree_detect.nbin");
  script_require_keys("installed_sw/SourceTree");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");
include("global_settings.inc");

# Paranoia - if the configuration for URI association is disabled then it may not be vulnerable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"SourceTree");

#atlassian_sourcetree add conversions for b --> beta and a --> alpha  
vcf::atlassian_sourcetree::initialize(); 

constraints = [{ "min_version" : "0.5a", "fixed_version" : "3.1.3" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
