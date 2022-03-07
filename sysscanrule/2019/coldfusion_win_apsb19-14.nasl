#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122535);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id("CVE-2019-7816");
  script_bugtraq_id(107211);

  script_name(english:"Adobe ColdFusion < 11.x < 11u18 / 2016.x < 2016u10 / 2018.x < 2018u3 Vulnerability (APSB19-14)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by a
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host
is prior to 11.x update 18, 2016.x update 10, or 2018.x update 3. It
is, therefore, affected by a vulnerability as referenced in the
APSB19-14 advisory.

  - File Upload Restriction Bypass potentially leading to
    Arbitrary code execution (CVE-2019-7816)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-14.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 11 update 18 / 2016 update 10 /
2018 update 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7816");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('coldfusion_win.inc');
include('global_settings.inc');
include('misc_func.inc');

instances = get_coldfusion_instances(); # this exits if it fails

# Check the hotfixes and cumulative hotfixes
# installed for each instance of ColdFusion.
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == '11.0.0')
  {
    info = check_jar_chf(name, 18);
  }

  else if (ver == '2016.0.0')
  {
    info = check_jar_chf(name, 10);
  }
  else if (ver == '2018.0.0')
  {
    info = check_jar_chf(name, 3);
  }
  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Adobe ColdFusion');

port = get_kb_item('SMB/transport');
if (!port)
  port = 445;

report =
  '\n' + 'GizaNE detected the following unpatched instances :' +
  '\n' + join(instance_info, sep:'\n') +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
