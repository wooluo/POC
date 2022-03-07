#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126049);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/20 11:24:24");

  script_cve_id(
    "CVE-2019-5666",
    "CVE-2019-5675",
    "CVE-2019-5676",
    "CVE-2019-5677"
  );

  script_name(english:"NVIDIA Windows GPU Display Driver Multiple Vulnerabilities (May 2019)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a security update. It is, therefore,
affected by multiple vulnerabilities:

  - An unspecified vulnerability exists in the kernel mode layer (nvvlddmkm.sys) handler for DxgkDdiEscape due to
    improper synchronization of shared data. An authenticated, local attacker can exploit this, to cause a denial of
    service, gain elevated privileges or to disclose potentially sensitive information. (CVE-2019-5675)

  - A binary planting vulnerability exists due to improper path or signature validation. An authenticated, local
    attacker can exploit this, via code execution to gain elevated privileges. (CVE-2019-5676)

  - A memory corruption vulnerability exists in the kernel mode layer (nvlddmkm.sys) handler for DeviceIoControl. An
    authenticated, local attacker can exploit this, to cause a denial of service condition. (CVE-2019-5677)
");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/4797
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
  # CVSSv2 authentication for CVE-2019-5675 tweaked from none to single, since local access is required

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

app_name = 'NVIDIA Driver';

# it is not possible to tell if these are vendor provided drivers or from the NVIDIA website
# some vendor provided version come with a fix (i.e. 430.23, 425.25, and 422.02)
if (report_paranoia < 2) audit(AUDIT_PARANOID);

kb_base = 'WMI/DisplayDrivers/';

# double check in case optimization is disabled
kbs = get_kb_list(kb_base + '*/Name');
if (isnull(kbs)) exit(0, 'No display drivers were found.');

foreach kb (keys(kbs))
{
  name = tolower(kbs[kb]);
  if ('nvidia' >!< name) continue;

  id = kb - kb_base - '/Name';
  version = get_kb_item_or_exit(kb_base + id + '/Version');
  gpumodel = tolower(get_kb_item_or_exit(kb_base + id + '/Processor'));
  break;
}

fix = NULL;
# Geforce or Quadro NVS
# All R430 versions prior to 430.64
if (gpumodel =~ "geforce|quadro|nvs" && version =~ "^430\.")
  fix = '430.64';

# Quadro NVS
if (gpumodel =~ "quadro|nvs") {
  # All R418 versions prior to 425.51
  if (version =~ "^4(1[89]|2[0-5])\.")
    fix = '425.51';

  # All R410 versions prior to 412.36
  else if (version =~ "^41[0-2]\.")
    fix = '412.36';

  # All R390 versions prior to 392.53
  else if (version =~ "^39[0-2]\.")
    fix = '392.53';
}
# Tesla
if (gpumodel =~ "tesla") {
  # All R418 versions prior to 425.25
  if (version =~ "^4(1[89]|2[0-5])\.")
    fix = '425.25';

  # All R410 versions prior to 412.36
  else if (version =~ "^41[0-2]\.")
    fix = '412.36';
}

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report = '\n  Installed driver version : ' + version +
           '\n  Fixed driver version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra: report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

