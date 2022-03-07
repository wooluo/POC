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
  script_id(125217);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/17 15:06:54");

  script_cve_id(
    "CVE-2019-0820",
    "CVE-2019-0980",
    "CVE-2019-0981",
    "CVE-2019-0982"
  );
  script_bugtraq_id(108245, 108207, 108208);
  script_xref(name:"IAVA", value:"2019-A-0149");

  script_name(english:"Security Update for .NET Core (May 2019)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core installation on the remote host is version
1.0.x < 1.0.16, 1.1.x < 1.1.13, 2.1.x < 2.1.11, 2.2.x < 2.2.5.
It is, therefore, affected by a denial of service (DoS) vulnerability when
.NET Core improperly handles web requests. An unauthenticated,
remote attacker could exploit this issue, via sending a specially
crafted requests to the .NET Core application, to cause the
application to stop responding.");
  # https://devblogs.microsoft.com/dotnet/net-core-may-2019/
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/dotnet/announcements/issues/111
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/dotnet/announcements/issues/112
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/dotnet/announcements/issues/113
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/aspnet/Announcements/issues/359
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0980");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');

app = '.NET Core Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '1.0', 'fixed_version' : '1.0.16.5115', 'fixed_display' : '1.0.16 (1.0.16.5115)' },
  { 'min_version' : '1.1', 'fixed_version' : '1.1.13.1809', 'fixed_display' : '1.1.13 (1.1.13.1809)' },
  { 'min_version' : '2.1', 'fixed_version' : '2.1.11.27618', 'fixed_display' : '2.1.11 (2.1.11.27618)' },
  { 'min_version' : '2.2', 'fixed_version' : '2.2.5.27618', 'fixed_display' : '2.2.5 (2.2.5.27618)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
