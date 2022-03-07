#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125880);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/14 12:01:44");

  script_cve_id("CVE-2019-7838", "CVE-2019-7839", "CVE-2019-7840");
  script_xref(name:"IAVA", value:"2019-A-0188");

  script_name(english:"Adobe ColdFusion < 11.x < 11u19 / 2016.x < 2016u11 / 2018.x < 2018u4 Multiple Vulnerabilities (APSB19-27)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 11.x update 19, 2016.x update 11, or
2018.x update 4. It is, therefore, affected by multiple vulnerabilities as referenced in the APSB19-27 advisory.

  - File extension blacklist bypass potentially leading to
    Arbitrary code execution (CVE-2019-7838)

  - Command Injection potentially leading to Arbitrary code
    execution (CVE-2019-7839)

  - Deserialization of untrusted data potentially leading to
    Arbitrary code execution (CVE-2019-7840)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-27.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 11 update 19 / 2016 update 11 / 2018 update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7840");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    info = check_jar_chf(name, 19);
  }

  else if (ver == '2016.0.0')
  {
    info = check_jar_chf(name, 11);
  }
  else if (ver == '2018.0.0')
  {
    info = check_jar_chf(name, 4);
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

