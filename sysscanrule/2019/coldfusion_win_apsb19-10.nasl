#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122236);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/07 13:55:32");

  script_cve_id("CVE-2019-7091", "CVE-2019-7092");
  script_bugtraq_id(106968, 106965);

  script_name(english:"Adobe ColdFusion < 11.x < 11u16 / 2016.x < 2016u8 / 2018.x < 2018u2 Multiple Vulnerabilities (APSB19-10)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host
is prior to 11.x update 16, 2016.x update 8, or 2018.x update 2. It
is, therefore, affected by multiple vulnerabilities as referenced in
the APSB19-10 advisory.

  - Deserialization of untrusted data potentially leading to
    Arbitrary code execution (CVE-2019-7091)

  - Cross site scripting potentially leading to Information
    Disclosure (CVE-2019-7092)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-10.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 11 update 16 / 2016 update 8 / 2018
update 2 or later.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7091");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

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
    info = check_jar_chf(name, 16);
  }

  else if (ver == '2016.0.0')
  {
    info = check_jar_chf(name, 8);
  }
  else if (ver == '2018.0.0')
  {
    info = check_jar_chf(name, 2);
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
