#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123516);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 15:17:20");

  script_cve_id(
    "CVE-2019-5515",
    "CVE-2019-5518",
    "CVE-2019-5519",
    "CVE-2019-5524"
  );
  script_xref(name:"VMSA", value:"2019-0005");
  script_xref(name:"IAVA", value:"2019-A-0099");

  script_name(english:"VMware Workstation 14.x < 14.1.7 / 15.x < 15.0.4 Multiple Vulnerabilities (VMSA-2019-0005)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by an uninitialized stack memory usage vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote
host is 14.x prior to 14.1.4 or 15.x prior to 15.0.1. It is,
therefore, affected by multiple vulnerabilities, including:

  - An out-of-bounds read/write vulnerability and a Time-of-check
    Time-of-use (TOCTOU) vulnerability in the virtual USB 1.1 UHCI
    (Universal Host Controller Interface). Exploitation of these
    issues requires an attacker to have access to a virtual machine
    with a virtual USB controller present. These issues may allow a
    guest to execute code on the host. (CVE-2019-5518, CVE-2019-5519)

  - An out-of-bounds write vulnerability in the e1000 virtual network
    adapter. This issue may allow a guest to execute code on the
    host. (CVE-2019-5524)

  - An out-of-bounds write vulnerability in the e1000 and e1000e
    virtual network adapters. Exploitation of this issue may lead to
    code execution on the host from the guest but it is more likely
    to result in a denial of service of the guest. (CVE-2019-5515)

Note that CVE-2019-5524 only applies to VMware Workstation 14.x and
was fixed in 14.1.6.

Note that CVE-2019-5515 was fixed in 14.1.6 and 15.0.3.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 14.1.7, 15.0.4, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5518");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { "min_version" : "14", "fixed_version" : "14.1.7" },
  { "min_version" : "15", "fixed_version" : "15.0.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

