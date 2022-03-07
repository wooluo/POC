#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124325);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/20 14:58:24");

  script_cve_id("CVE-2019-1710");
  script_bugtraq_id(108007);
  script_xref(name: "CWE", value: "CWE-20");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvn56004");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190417-asr9k-exr");

  script_name(english:"Cisco IOS XR 64-Bit Software for Cisco ASR 9000 Series Aggregation Services Routers Network Isolation Vulnerability");
  script_summary(english:"Checks the version of Cisco ASR 9000 Series Aggregation Services Routers");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASR 9000 Series
Aggregation Services Routers are affected by the following vulnerability :

  - A vulnerability in the sysadmin virtual machine (VM) on
    Cisco ASR 9000 Series Aggregation Services Routers
    running Cisco IOS XR 64-bit Software could allow an
    unauthenticated, remote attacker to access internal
    applications running on the sysadmin VM.The
    vulnerability is due to incorrect isolation of the
    secondary management interface from internal sysadmin
    applications. An attacker could exploit this
    vulnerability by connecting to one of the listening
    internal applications. A successful exploit could result
    in unstable conditions, including both a denial of
    service and remote unauthenticated access to the device.
    (CVE-2019-1710)

A workaround exists for this vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-asr9k-exr
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn56004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version or apply the workaround
referenced in advisory cisco-sa-20190417-asr9k-exr");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1710");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_9000_series_aggregation_services_routers");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if (product_info.model !~ "^9[09]\d\dv?")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info.model + ' model');

vuln_ranges =
  [ {'min_ver':'6', 'fix_ver':'6.5.3'},
    {'min_ver':'7', 'fix_ver':'7.0.1'}
  ];


workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn56004'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
