#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126987);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/24 10:28:43");

  script_cve_id(
    "CVE-2018-1922",
    "CVE-2018-1923",
    "CVE-2018-1936",
    "CVE-2018-1978",
    "CVE-2018-1980",
    "CVE-2019-4014",
    "CVE-2019-4015",
    "CVE-2019-4016",
    "CVE-2019-4094"
  );
  script_bugtraq_id(
    107398,
    107439,
    107686,
    107985
  );
  script_xref(name:"IAVB", value:"2019-B-0054");

  script_name(english:"IBM Spectrum Protect 7.1.x < 7.1.9.300 / 8.1.x < 8.1.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM Spectrum Protect.");

  script_set_attribute(attribute:"synopsis", value:
"The backup service installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM Spectrum Protect, formerly known as Tivoli Storage Manager,
installed on the remote host is version 7.1.x < 7.1.9.300 or 8.1.x <
8.1.8. It is, therefore, affected by multiple IBM Db2 remote code
execution and privilege escalation vulnerabilities. These
vulnerabilities could allow an attacker to gain system-level access to
the affected host.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=ibm10882974");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect 7.1.9.300 or 8.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1922");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:spectrum_protect");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tsm_detect.nasl", "ibm_spectrum_protect_installed.nbin");
  script_require_ports("installed_sw/IBM Tivoli Storage Manager", "installed_sw/IBM Spectrum Protect");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

port = get_service(svc:'tsm-agent');

app_info = vcf::ibm::spectrum_protect::get_app_info(port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '7.1', 'max_version' : '7.1.9.200', 'fixed_version' : '7.1.9.300' },
  { 'min_version' : '8.1', 'fixed_version' : '8.1.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
