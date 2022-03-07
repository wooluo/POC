
##
# 
##


include('compat.inc');

if (description)
{
  script_id(153214);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2021-40444");

  script_name(english:"Security Updates for Microsoft Internet Explorer OOB (Sept 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Internet Explorer installation on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Internet Explorer installation on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444");
  script_set_attribute(attribute:"solution", value:
"Review the Microsoft advisory for registry settings & workaround guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:C/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40444");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");
var os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (("Windows 8" >< productname && "8.1" >!< productname) || "Vista" >< productname)
 audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
var key, res, hklm;
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# if these keys are not set, all of them, to 3, you are vuln...
var keys2chk = make_list(
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1001",
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1001",
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1001",
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001",
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1004",
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1004",
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1004",
  "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004"
);

var report = 'The following registry keys were missing or not set correctly: \n' ; 
var vuln = FALSE;

foreach var zone_chks (keys2chk)
{
    res = get_registry_value(handle:hklm, item:zone_chks); 

    if (empty_or_null(res))
    {
      report += ' - ' + zone_chks + ' is empty.\n';
      vuln = TRUE;
    }
    else if (res != 3)
    {
      report += ' - ' + zone_chks + ' is set to [' + res + '].\n';
      vuln = TRUE;
    }
}

if (vuln)
{
  var port = kb_smb_transport();
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_VER_NOT_VULN, 'Internet Explorer');
}