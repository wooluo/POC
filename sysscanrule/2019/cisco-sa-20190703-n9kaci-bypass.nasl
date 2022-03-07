#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126629);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/12  8:16:17");

  script_cve_id("CVE-2019-1890");
  script_bugtraq_id(109052);
  script_xref(name:"IAVA", value:"2019-A-0217");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvp64280");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190703-n9kaci-bypass");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode Fabric Infrastructure VLAN Unauthorized Access Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS System Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software in
ACI mode is affected by a security bypass vulnerability. An
unauthenticated, adjacent attacker could exploit this vulnerability to
connect an unauthorized server to the highly privileged infrastructure
VLAN. Please see the included Cisco BIDs and Cisco Security Advisory
for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-n9kaci-bypass
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp64280");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp64280");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1890");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info['device'] || product_info['model'] !~ '^90[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '11.0.1b',
  '11.0.1c',
  '11.0.1d',
  '11.0.1e',
  '11.0.2j',
  '11.0.2m',
  '11.0.3f',
  '11.0.3i',
  '11.0.3k',
  '11.0.3n',
  '11.0.3o',
  '11.0.4h',
  '11.0.4o',
  '11.0.4q',
  '11.0.4g',
  '11.1.1j',
  '11.1.1o',
  '11.1.1r',
  '11.1.1s',
  '11.1.2h',
  '11.1.2i',
  '11.1.3f',
  '11.1.4',
  '11.1.4e',
  '11.1.4f',
  '11.1.4g',
  '11.1.4i',
  '11.1.4l',
  '11.1.4m',
  '11.2.1i',
  '11.2.2g',
  '11.2.3c',
  '11.2.2h',
  '11.2.2i',
  '11.2.3e',
  '11.2.3h',
  '11.2.3m',
  '11.2.1k',
  '11.2.1m',
  '11.2.2j',
  '12.0.1m',
  '12.0.2g',
  '12.0.1n',
  '12.0.1o',
  '12.0.1p',
  '12.0.1q',
  '12.0.2h',
  '12.0.2l',
  '12.0.2m',
  '12.0.2n',
  '12.0.2o',
  '12.0.2f',
  '12.0.1r',
  '12.1.1h',
  '12.1.2e',
  '12.1.3g',
  '12.1.4a',
  '12.1.1i',
  '12.1.2g',
  '12.1.2k',
  '12.1.3h',
  '12.1.3j',
  '12.2.1n',
  '12.2.2e',
  '12.2.3j',
  '12.2.4f',
  '12.2.4p',
  '12.2.3p',
  '12.2.3r',
  '12.2.3s',
  '12.2.3t',
  '12.2.2f',
  '12.2.2g',
  '12.2.2i',
  '12.2.2j',
  '12.2.2k',
  '12.2.2q',
  '12.2.1o',
  '12.2.4q',
  '12.2.4r',
  '12.2.1k',
  '12.3.1e',
  '12.3.1f',
  '12.3.1i',
  '12.3.1l',
  '12.3.1o',
  '12.3.1p',
  '13.0.1k',
  '13.0.2h',
  '13.0.2k',
  '13.0.2n',
  '13.0.1i',
  '13.0.2m',
  '13.1.1i',
  '13.1.2m',
  '13.1.2o',
  '13.1.2p',
  '13.1.2q',
  '13.1.2s',
  '13.1.2t',
  '13.1.2u',
  '13.2.1l',
  '13.2.1m',
  '13.2.2l',
  '13.2.2o',
  '13.2.3i',
  '13.2.3n',
  '13.2.3o',
  '13.2.3r',
  '13.2.4d',
  '13.2.4e',
  '13.2.3j',
  '13.2.3s',
  '13.2.5d',
  '13.2.5e',
  '13.2.5f',
  '13.2.6i',
  '11.3.1g',
  '11.3.2f',
  '11.3.1h',
  '11.3.1i',
  '11.3.2h',
  '11.3.2i',
  '11.3.2k',
  '11.3.1j',
  '11.3.2j',
  '14.0.1h',
  '14.0.2c',
  '14.0.3d',
  '14.0.3c',
  '14.1.1i',
  '14.1.1j',
  '14.1.1k',
  '14.1.1l'
);

workarounds = make_list(CISCO_WORKAROUNDS['aci_secmode_strict']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp64280'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
