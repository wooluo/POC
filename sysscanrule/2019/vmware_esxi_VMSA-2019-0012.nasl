#
# (C) WebRAY Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(128035);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 15:38:19");

  script_cve_id("CVE-2019-5521", "CVE-2019-5684");
  script_bugtraq_id(93287);
  script_xref(name:"VMSA", value:"2019-0012");
  script_xref(name:"IAVA", value:"2019-A-0278");

  script_name(english:"ESXi 6.5 / 6.7 Multiple Vulnerabilities (VMSA-2019-0012)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by pixel shader out-of-bounds read/write vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 6.5 or 6.7 and is affected by
multiple vulnerabilities.  Note that GizaNE has not tested for these
issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0012.html");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5684");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array(
  '6.5', '13932383',
  '6.7', '13981272'
);

rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

ver = get_kb_item_or_exit('Host/VMware/version');

match = pregmatch(pattern:'^ESXi? ([0-9]+\\.[0-9]+).*$', string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7');
ver = match[1];

if (ver !~ '^6\\.(5|7)$') audit(AUDIT_OS_NOT, 'ESXi 6.5 / 6.7');

fixed_build = int(fixes[ver]);

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7');

build = int(match[1]);

if (!(build < fixed_build)) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_build +
         '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
