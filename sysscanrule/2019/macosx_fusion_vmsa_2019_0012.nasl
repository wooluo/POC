#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127135);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 15:23:38");
  script_xref(name:"IAVA", value:"2019-A-0278");

  script_cve_id("CVE-2019-5521", "CVE-2019-5684");
  script_bugtraq_id(93287);
  script_xref(name:"VMSA", value:"2019-0012");

  script_name(english:"VMware Fusion 10.0.x < 10.1.6 / 11.0.x < 11.0.3 Pixel Shader out-of-bounds read/write vulnerabilities (VMSA-2019-0012)");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X host is affected by pixel shader out-of-bounds read/write vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or Mac OS X host is 10.0.x prior to 10.1.6 or 11.0.x prior to
11.0.3. It is, therefore, affected by multiple vulnerabilities.  Note that GizaNE has not tested for these issues but
has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0012.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Fusion version 10.1.6, 11.0.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5684");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include('vcf.inc');


app_info = vcf::get_app_info(app:'VMware Fusion');

constraints = [
  { 'min_version' : '10.0', 'fixed_version' : '10.1.6' },
  { 'min_version' : '11.0', 'fixed_version' : '11.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
