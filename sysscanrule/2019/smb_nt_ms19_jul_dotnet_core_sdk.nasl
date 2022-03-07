#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(126602);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/11  8:48:18");

  script_cve_id("CVE-2019-1075");
  script_bugtraq_id(108984);

  script_name(english:"Security Update for .NET Core SDK (July 2019)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core SDK vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core SDK installation on the remote host is version
2.1.x < 2.1.508 or 2.1.605 or 2.1.701, 2.2.x < 2.2.108 or 2.2.205 or 2.2.301.
It is, therefore, affected by a spoofing vulnerability that could lead to an open redirect.
An unauthenticated, remote attacker could exploit this issue, via a link that has a specially crafted URL,
and convince the user to click the link that will redirect a targeted user to a malicious website");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1075
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/aspnet/Announcements/issues/373
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/aspnet/AspNetCore/issues/12007
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1075");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = '.NET Core SDK Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '2.1', 'fixed_version' : '2.1.508' },
  { 'min_version' : '2.1.600', 'fixed_version' : '2.1.605'},
  { 'min_version' : '2.1.700', 'fixed_version' : '2.1.701'},
  { 'min_version' : '2.2', 'fixed_version' : '2.2.108' },
  { 'min_version' : '2.2.200', 'fixed_version' : '2.2.205'},
  { 'min_version' : '2.2.300', 'fixed_version' : '2.2.301'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
