#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122510);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/01  9:57:10");

  script_cve_id(
    "CVE-2018-6260",
    "CVE-2019-5665",
    "CVE-2019-5666",
    "CVE-2019-5667",
    "CVE-2019-5668",
    "CVE-2019-5669",
    "CVE-2019-5670",
    "CVE-2019-5671"
  );
  script_xref(name:"IAVA", value:"2019-A-0063");

  script_name(english:"NVIDIA Windows GPU Display Driver Multiple Vulnerabilities (February 2019)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing
a security update. It is, therefore, affected by multiple
vulnerabilities:

  - A vulnerability in the 3D vision component in which the stereo
    service software, when opening a file, does not check for hard
    links. This behavior may lead to code execution, denial of
    service or escalation of privileges. (CVE-2019-5665)

  - A vulnerability in the kernel mode layer (nvlddmkm.sys) create
    context command DDI DxgkDdiCreateContext in which the product
    uses untrusted input when calculating or using an array index,
    but the product does not validate or incorrectly validates the
    index to ensure the index references a valid position within the
    array, which may lead to denial of service or escalation of
    privileges. (CVE-2019-5666)

  - A vulnerability in the kernel mode layer (nvlddmkm.sys) handler
    for DxgkDdiSetRootPageTable in which the application dereferences
    a pointer that it expects to be valid, but is NULL, which may
    lead to code execution, denial of service or escalation of
    privileges. (CVE-2019-5667)

It is also affected by additional vulnerabilities including denial of
service, privilege escalation, code execution, and information
disclosure vulnerabilities. See the vendor advisory for details.");
 script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4772");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5665");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity",value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

kb_base = 'WMI/DisplayDrivers/';

# double check in case optimization is disabled
kbs = get_kb_list(kb_base + '*/Name');
if (isnull(kbs)) exit(0, 'No display drivers were found.');

report = '';

foreach kb (keys(kbs))
{
  name = kbs[kb];
  # only check NVIDIA drivers
  if ("NVIDIA" >!< name) continue;

  nvidia_found = TRUE;
  id = kb - kb_base - '/Name';
  version = get_kb_item_or_exit(kb_base + id + '/Version');
  driver_date = get_kb_item_or_exit(kb_base + id + '/DriverDate');

  disp_driver_date = driver_date;

  # convert to something we can pass to ver_compare (YYYY.MM.DD)
  driver_date = split(driver_date, sep:'/', keep:FALSE);
  driver_date = driver_date[2] + '.' + driver_date[0] + '.' + driver_date[1];

  fix = NULL;
  # All R418 versions prior to 419.17
  if (version =~ "^41[89]\." && ver_compare(ver:version, fix:"419.17", strict:FALSE) == -1)
    fix = "419.17";
  # All R400 versions prior to 412.29
  else if (version =~ "^4(0[0-9]|1[0-2])\." && ver_compare(ver:version, fix:"412.29", strict:FALSE) == -1)
    fix = "412.29";
  # All R390 versions prior to 392.37
  else if (version =~ "^39[0-2]\." && ver_compare(ver:version, fix:"392.37", strict:FALSE) == -1)
    fix = "392.37";

  if(!isnull(fix))
  {
    order = make_list('Device name','Driver version','Driver date','Fixed version');
    report = make_array(
      order[0],name,
      order[1],version,
      order[2],disp_driver_date,
      order[3],fix
      );

    report = report_items_str(report_items:report, ordered_fields:order);
    security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
    exit(0);
  }
  else
  {
    exit(0, "No vulnerable NVIDIA display drivers were found.");
  }
}

exit(0, 'No NVIDIA display drivers were found.');
