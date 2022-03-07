#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123002);
  script_version("1.6");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id("CVE-2019-5511","CVE-2019-5512");
  script_bugtraq_id(107429);
  script_xref(name:"VMSA", value:"2019-0002");

  script_name(english:"VMware Workstation 14.x < 14.1.6 / 15.x < 15.0.3 Elevation of Privilege Vulnerability (VMSA-2019-0002)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote
host is 14.x prior to 14.1.6 or 15.x prior to 15.0.3. It is,
therefore, affected by an elevation of privilege vulnerability in the
creation of the VMX process on a windows host.
An attacker with access to a host system may be able to hijack
the path to the VMX executable or COM classes used by the VMX 
process leading to an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0002.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 14.1.6, 15.0.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5511");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("installed_sw/VMware Workstation");

  exit(0);
}

include("vcf.inc");

if (get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;

app_info = vcf::get_app_info(app:"VMware Workstation", win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "14", "fixed_version" : "14.1.6" },
  { "min_version" : "15", "fixed_version" : "15.0.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

