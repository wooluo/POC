#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122778);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/15 15:35:01");

  script_cve_id("CVE-2019-0757");
  script_xref(name:"IAVA", value:"2019-A-0084");

  script_name(english:"Security Update for .NET Core SDK (March 2019)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a tampering vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of .NET Core SDK with a
version of 1.x < 1.1.13 or 2.1.x < 2.1.505. Therefore, the host is
affected by a tampering vulnerability with in the NuGet Package
Manager. An authenticated, attacker can exploit this, via manipulating
the folder contents prior to building or installing a application, to
modify files and folders after unpacking.");
  script_set_attribute(attribute:"see_also",value:"https://github.com/dotnet/announcements/issues/103");
  # https://github.com/dotnet/core/blob/master/release-notes/1.0/1.0.15/1.0.15.md
  script_set_attribute(attribute:"see_also",value:"");
  # https://github.com/dotnet/core/blob/master/release-notes/1.1/1.1.12/1.1.12.md
  script_set_attribute(attribute:"see_also",value:"");
  # https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.9/2.1.9.md
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0757");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows");

  exit(0);
}

include('vcf.inc');

app = '.NET Core SDK Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '1.0', 'fixed_version' : '1.1.13'},
  { 'min_version' : '2.1', 'fixed_version' : '2.1.505'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
