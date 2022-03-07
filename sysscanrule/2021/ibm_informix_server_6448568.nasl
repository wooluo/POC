##
# 
##


include('compat.inc');

if (description)
{
  script_id(149349);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2021-20515");
  script_xref(name:"IAVA", value:"2021-A-0209");

  script_name(english:"IBM Informix Dynamic Server 14.10.x < 14.10.xC5 Buffer Overflow (6448568)");

  script_set_attribute(attribute:"synopsis", value:
"A database server installed on the remote host is affected by a buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Informix Dynamic Server installed on the remote is 14.10.x prior to 14.10.xC5. It is, therefore,
affected by a buffer overflow, caused by improper bounds checking. A local privileged user could overflow a buffer and
execute arbitrary code on the system or cause a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6448568");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Informix Dynamic Server to the fixed version mentioned in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_informix_server_installed.nasl");
  script_require_keys("installed_sw/IBM Informix Dynamic Server");

  exit(0);
}

include('vcf.inc');

var app_name = 'IBM Informix Dynamic Server';
var install = vcf::get_app_info(app:app_name, win_local:TRUE);

var ver   = install['version'];
var path  = install['path'];
var fix = NULL;

if (ver !~ "^14\.10\.")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

var item = pregmatch(pattern:"[cC]([0-9]+)([^0-9]|$)", string:ver);
if (!empty_or_null(item) && !empty_or_null(item[1]) && item[1] < 5)
  fix = '14.10.xC5';

if (empty_or_null(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

var port = get_kb_item("SMB/transport");
if (!port) port = 445;

var report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix + '\n';

var server_instances = get_kb_item("Host/" + app_name + "/Server Instances");

if (!empty_or_null(server_instances))
{
  var instance_list = split(server_instances, sep:' / ', keep:FALSE);
  report += '  Server instances  : ' + '\n      - ' + join(instance_list, sep:'\n      - ') + '\n';
}

security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
