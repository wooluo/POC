#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(127856);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/16 16:24:22");

  script_cve_id("CVE-2019-1201");
  script_xref(name:"MSKB", value:"4475533");
  script_xref(name:"MSKB", value:"4475547");
  script_xref(name:"MSKB", value:"4475540");
  script_xref(name:"MSFT", value:"MS19-4475533");
  script_xref(name:"MSFT", value:"MS19-4475547");
  script_xref(name:"MSFT", value:"MS19-4475540");
  script_xref(name:"IAVA", value:"2019-A-0291");

  script_name(english:"Security Updates for Microsoft Word Products (August 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Word product is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A Microsoft Word product is missing security updates. It is,
therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-1201)");
  # https://support.microsoft.com/en-us/help/4475533/security-update-for-word-2010-august-13-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475547/security-update-for-word-2013-august-13-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475540/security-update-for-word-2016-august-13-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4475533
  -KB4475547
  -KB4475540");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1201");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-08";
kbs = make_list(
4475533,
4475547,
4475540
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

checks = make_array(

  "14.0", make_array("sp", 2, "version", "14.0.7236.5000", "kb", "4475533"),
  "15.0", make_array("sp", 1, "version", "15.0.5163.1000", "kb", "4475547"),
  "16.0", make_nested_list(make_array("sp", 0, "version", "16.0.4888.1000", "channel", "MSI", "kb", "4475540"),
    # C2R
    make_array("version", "16.0.9126.2432", "channel", "Deferred"),
    make_array("version", "16.0.10730.20370", "channel", "Deferred", "channel_version", "1808"),
    make_array("version", "16.0.11328.20392", "channel", "Deferred", "channel_version", "1902"),
    make_array("version", "16.0.11328.20392", "channel", "First Release for Deferred"),
    make_array("version", "16.0.11901.20218", "channel", "Current"),
    # 2019
    make_array("version", "16.0.11901.20218", "channel", "2019 Retail"),
    make_array("version", "16.0.10349.20017", "channel", "2019 Volume"))
  );

if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}