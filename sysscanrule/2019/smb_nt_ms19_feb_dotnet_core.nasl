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
  script_id(122154);
  script_version("1.3");
  script_cvs_date("Date: 2019/02/26  4:50:09");

  script_cve_id("CVE-2019-0657");
  script_xref(name:"IAVA", value:"2019-A-0044");

  script_name(english:"Security Update for .NET Core (February 2019)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core domain spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of .NET Core with a
version of 1.0.x < 1.0.14, 1.1.x < 1.1.11, 2.1.x < 2.1.8 or
2.2x < 2.2.2. Therefore, the host is affected by the following:

  - A Domain spoofing vulnerability which causes the meaning of a
  URI to change when International Domain Name encoding is applied.
  An attacker who successfully exploited the vulnerability could
  redirect a URI. (CVE-2019-0657)");
  # https://github.com/dotnet/announcements/issues/97
  script_set_attribute(attribute:"see_also",value:"");
  # https://github.com/dotnet/core/blob/master/release-notes/1.0/1.0.14/1.0.14.md
  script_set_attribute(attribute:"see_also",value:"");
    # https://github.com/dotnet/core/blob/master/release-notes/1.1/1.1.11/1.1.11.md
  script_set_attribute(attribute:"see_also",value:"");
    # https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.8/2.1.8.md
  script_set_attribute(attribute:"see_also",value:"");
    # https://github.com/dotnet/core/blob/master/release-notes/2.2/2.2.2/2.2.2.md
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0657");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/13");

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
  { 'min_version' : '1.0', 'fixed_version' : '1.0.14.5101', 'fixed_display' : '1.0.14 (1.0.14.5101)' },
  { 'min_version' : '1.1', 'fixed_version' : '1.1.11.1791', 'fixed_display' : '1.1.11 (1.1.11.1791)' },
  { 'min_version' : '2.1', 'fixed_version' : '2.1.8.27317', 'fixed_display' : '2.1.8 (2.1.8.27317)' },
  { 'min_version' : '2.2', 'fixed_version' : '2.2.2.27318', 'fixed_display' : '2.2.2 (2.2.2.27318)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
