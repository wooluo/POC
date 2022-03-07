#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122976);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/22 16:03:45");

  script_cve_id("CVE-2019-5513");
  script_bugtraq_id(107428);
  script_xref(name:"VMSA", value:"2019-0003");
  script_xref(name:"IAVA", value:"2019-A-0088");

  script_name(english:"VMware Horizon View 6.x < 6.2.8 / 7.x (CR) < 7.8.0 / 7.5.x (ESB) < 7.5.2 Information Disclosure (VMSA-2019-0003)");
  script_summary(english:"Checks the version of VMware Horizon View.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View installed on the remote Windows
host is 6.x prior to 6.2.8, 7.x (CR) prior to 7.8.0, or 7.5.x (ESB)
prior to 7.5.2. It is, therefore, affected by an unspecified flaw
in the 'Connection Server' that allows disclosure of sensitive
information, including but not limited to, internal gateway IP
address, internal domain names, and other information.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0003.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View version 6.2.8 / 7.5.2 (ESB) /
7.8.0 (CR) or later and apply the vendor-suggested configuration
settings.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5513");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"VMware Horizon View", win_local:TRUE);

# need to filter out the agent as connection server only resides on the server
if (! empty_or_null(app_info['Install type']) && app_info['Install type'] =='Agent'  ) audit(AUDIT_INST_VER_NOT_VULN, 'VMWare Horizon Agent');

# Vendor has introduced 'ESB' and 'CR' branches.
# Vuln :
#        Normal :  6.x < 6.2.8
#        CR     :  7.5.x < 7.5.2
#        ESB    :  7.x < 7.5 and 7.6.x, 7.7.x
constraints = [
  { "min_version" : "6",   "fixed_version" : "6.2.8" },
  { "min_version" : "7.5", "fixed_version" : "7.5.2", "fixed_display" : "7.5.2 (ESB)" },
  { "min_version" : "7",   "fixed_version" : "7.5",   "fixed_display" : "7.8.0 (CR)"  },
  { "min_version" : "7.6", "fixed_version" : "7.8",   "fixed_display" : "7.8.0 (CR)" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
