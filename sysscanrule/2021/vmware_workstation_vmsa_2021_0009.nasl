##
# 
##


include('compat.inc');

if (description)
{
  script_id(149853);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/25");

  script_cve_id("CVE-2021-21987", "CVE-2021-21988", "CVE-2021-21989");
  script_xref(name:"VMSA", value:"2021-0009");

  script_name(english:"VMware Workstation 16.0.x < 16.1.2 Multiple Vulnerabilities (VMSA-2021-0009)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host is 16.0.x prior to 16.1.2. It is, therefore,
affected by multiple vulnerabilities.  Note that Nessus has not tested for these issues but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0009.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadworkstation");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Workstation-Pro/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadplayer");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Workstation-Player/index.html");
  # https://my.vmware.com/en/web/vmware/downloads/info/slug/desktop_end_user_computing/vmware_horizon_clients/horizon_7_5_0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adda9df7");
  # https://docs.vmware.com/en/VMware-Horizon-Client-for-Windows/5.5.2/rn/horizon-client-windows-552-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31393d1e");
  # https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d34c091e");
  # https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d34c091e");
  # https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5ac3df7");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 16.1.2, or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("Host/VMware Workstation/Version", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

constraints = [
  { 'min_version' : '16.0', 'fixed_version' : '16.1.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
