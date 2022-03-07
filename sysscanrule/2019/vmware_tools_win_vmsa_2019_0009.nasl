#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125884);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/21  5:26:55");

  script_cve_id("CVE-2019-5522");
  script_bugtraq_id(108673);
  script_xref(name:"VMSA", value:"2019-0009");
  script_xref(name:"IAVB", value:"2019-B-0046");

  script_name(english:"VMware Tools 10.2.x / 10.3.x < 10.3.10 Information Disclosure / Denial of Service Vulnerability (VMSA-2019-0009)");
  script_summary(english:"Checks the VMware Tools version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization tool suite is installed on the remote Windows host is affected by an information disclosure / denial 
of service vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is 10.2.x / 10.3.s prior to 10.3.10. It is, therefore,
affected by an information disclosure / denial of service vulnerability due to an out of bounds read vulnerability in
the vm3dmp driver which is installed with vmtools. An authenticated, local attacker could exploit this to leak kernel
information or create a denial of service attack against the guest Windows machine vmtools is installed on. 

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0009.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Tools version 10.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5522");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vmware_tools");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin", "vmware_vsphere_detect.nbin","vmware_esxi_detection.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools", "Host/ESXi/checked");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'VMware Tools', win_local:TRUE);
constraints = [{ 'min_version' : '10.2.0', 'fixed_version' : '10.3.10' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
