#
# (C) WebRAY Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(125883);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/14 15:20:04");
  script_xref(name:"IAVA", value:"2019-A-0192");

  script_cve_id("CVE-2019-5525");
  script_bugtraq_id(108674);
  script_xref(name: "VMSA", value: "2019-0009");

  script_name(english:"VMware Workstation (Linux) 15.0.x < 15.1.0 Use After Free Vulnerability (VMSA-2019-0009)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Linux host is affected by a use after free vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Linux host is 15.0.x prior to 15.1.0. It is, therefore, 
affected by a use after free vulnerability in the Advanced Linux Sounds Architecture Backend. An authenticated, local 
attacker can exploit this, in conjunction with other issues, to execute arbitrary code. 

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0009.html");
  script_set_attribute(attribute:"solution", value:"Update to VMware Workstation version 15.1.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5525");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_require_keys("installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');
include('audit.inc');

# Vuln is Linux only
if(get_kb_item('SMB/Registry/Enumerated')) audit(AUDIT_HOST_NOT, 'affected');

app_info = vcf::get_app_info(app:"VMware Workstation", win_local:FALSE);

constraints = [
  { 'min_version' : '15.0.0', 'fixed_version' : '15.1.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
