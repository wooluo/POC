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
  script_id(123132);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/27  8:26:40");

  script_cve_id("CVE-2019-0545", "CVE-2018-8416");
  script_bugtraq_id(106405, 105798);

  script_name(english:"Security Update for .NET Core (January 2019)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core tampering and
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of .NET Core with a
version 2.1.x < 2.1.7 or 2.2.x < 2.2.1. 
It is, therefore, affected by the following vulnerabilities:

  - An information disclosure vulnerability exists in .NET Core.
  An unauthenticated, remote attacker can exploit this to bypass
  cross-origin resource sharing (CORS), to disclose potentially
  sensitive information. (CVE-2019-0545)

  - A tampering vulnerability exists in .NET Core. An
  authenticated, remote attacker can exploit this to write arbitrary
  files and directories with limited control of their destinations.
  (CVE-2018-8416)");
  # https://blogs.msdn.microsoft.com/dotnet/2019/01/08/net-core-january-2019-update/
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.7/2.1.7.md
  script_set_attribute(attribute:"see_also",value:"");
  # https://github.com/dotnet/core/blob/master/release-notes/2.2/2.2.1/2.2.1.md
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"solution", value:"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0545");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
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
  { 'min_version' : '2.1', 'fixed_version' : '2.1.7.27130', 'fixed_display' : '2.1.7 (2.1.7.27130)' },
  { 'min_version' : '2.2', 'fixed_version' : '2.2.1.27207', 'fixed_display' : '2.2.1 (2.2.1.27207)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
