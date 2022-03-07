#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126634);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id("CVE-2019-1008");
  script_bugtraq_id(108816);
  script_xref(name:"MSKB", value:"4494412");
  script_xref(name:"MSKB", value:"4498363");
  script_xref(name:"MSKB", value:"4499386");
  script_xref(name:"MSFT", value:"MS19-4494412");
  script_xref(name:"MSFT", value:"MS19-4498363");
  script_xref(name:"MSFT", value:"MS19-4499386");

  script_name(english:"Security Update for Microsoft Dynamics 365 (on-premises) (May 2019)");
  script_summary(english:"Checks the version of Microsoft Dynamics 365 (on-premises).");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a Microsoft Dynamics 365 (on-premises) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Dynamics 365 (on-premises) installed on
the remote Windows host is 7.x < 7.0.3.147, 8.x < 8.2.6.19, 9.x < 9.0.4.5. It is,
therefore, affected by a security feature bypass vulnerability.
An unauthenticated, remote attacker could exploit this issue, to send attachment types that are blocked
by the email attachment system.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1008
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-au/help/4498363/security-update-0-4-for-microsoft-dynamics-365-9-0
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4494412/security-dynamics-365-on-premises-update-2-6
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499386/security-update-for-vulnerabilities-in-microsoft-dynamics
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.microsoft.com/en-us/download/details.aspx?id=58299
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.microsoft.com/en-us/download/details.aspx?id=58297
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.microsoft.com/en-us/download/details.aspx?id=58298
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Dynamics 365 (on-premises) 7.0.3.147, 8.2.6.19, 9.0.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1008");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dynamics_365");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics 365 Server';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.0.3.147' },
  { 'min_version' : '8.0', 'fixed_version' : '8.2.6.19' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.4.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);