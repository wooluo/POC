#
# 
#

include('compat.inc');

if (description)
{
  script_id(140791);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2020-4643");
  script_xref(name:"IAVA", value:"2020-A-0431");

  script_name(english:"IBM WebSphere Application Server 7.0.0.x through 7.0.0.45 / 8.0.0.x through 8.0.0.15 / 8.5.x through to 8.5.5.17 / 9.0.x through to 9.0.5.5 XXE (CVE-2020-4643)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an XML External Entity Injection vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of WebSphere Application Server installed on the remote host is 7.0.0.x through 7.0.0.45, 8.0.0.x through
8.0.0.15, 8.5.x through 8.5.5.17, or 9.0.x through 9.0.5.5. It is, therefore, affected by a vulnerability as
referenced in the 6334311 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6334311");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4643");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"stig_severity", value:"I");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

app = 'IBM WebSphere Application Server';
app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PH27509' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [    
  {'min_version': '7.0.0.0', 'max_version': '7.0.0.45', 'fixed_display':'7.0.0.45 and then apply Interim Fix PH27509'},
  {'min_version': '8.0.0.0', 'max_version': '8.0.0.15', 'fixed_display':'8.0.0.15 and then apply Interim Fix PH27509'},
  {'min_version': '8.5.0.0', 'max_version': '8.5.5.17', 'fixed_display':'8.5.5.19 or apply Interim Fix PH27509'},
  {'min_version': '9.0.0.0', 'max_version': '9.0.5.5',  'fixed_display':'9.0.5.6 or apply Interim Fix PH27509'}
  ];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
