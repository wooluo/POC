##
# 
##

include('compat.inc');

if (description)
{
  script_id(145532);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value: "2021/01/27");

  script_cve_id("CVE-2020-6207");

  script_name(english:"SAP Solution Manager Missing Authentication (2890213)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP Solution Manager may be affected by a missing authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SAP Solution Manager SAP on the remote host may be affected by a missing authentication vulnerability 
in the End user Experience Monitoring (EEM) function due to a lack of authentication checks for a service. An
unauthenticated, remote attacker can exploit this issue to compromise all SMDAgents connected to the Solution Manager.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/2890213");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=540935305");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6207");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_solution_manager");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_solution_manager_web_detect.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/SAP Solution Manager");

  exit(0);
}

include('vcf.inc');
app_name = 'SAP Solution Manager';
app_info = vcf::get_app_info(app:app_name);

#  paranoid since we can't see the patch level
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:2);

if (app_info['version'] =~ "^7.2") {
  sps = app_info['SPS'];
  sps_fix = '12';
  if(!empty_or_null(sps) && ver_compare(ver:sps, fix:sps_fix) >= 0)
    audit(AUDIT_INST_VER_NOT_VULN, app_name, app_info['version'] + ' SP' + sps);
}

constraints = [{ 'min_version' : '7.2', 'fixed_version' : '7.3', 'fixed_display' : 'Refer to vendor advisory'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
