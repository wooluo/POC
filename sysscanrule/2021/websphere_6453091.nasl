##
# 
##


include('compat.inc');

if (description)
{
  script_id(149787);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id(
    "CVE-2011-1498",
    "CVE-2012-6153",
    "CVE-2014-3577",
    "CVE-2015-5262"
  );

  script_name(english:"IBM WebSphere Application Server 8.0.x <= 8.0.0.15 / 8.5.x < 8.5.5.20 / 9.0.x < 9.0.5.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of WebSphere Application Server installed on the remote host is 8.0.x through 8.0.0.15, 8.5.x prior to
8.5.5.20, or 9.0.x prior to 9.0.5.8. It is, therefore, affected by multiple vulnerabilities as referenced in the
6453091 advisory, including the following:

  - http/conn/ssl/SSLConnectionSocketFactory.java in Apache HttpComponents HttpClient before 4.3.6 ignores the
    http.socket.timeout configuration setting during an SSL handshake, which allows remote attackers to cause
    a denial of service (HTTPS call hang) via unspecified vectors. (CVE-2015-5262)

  - org.apache.http.conn.ssl.AbstractVerifier in Apache HttpComponents HttpClient before 4.3.5 and
    HttpAsyncClient before 4.0.2 does not properly verify that the server hostname matches a domain name in
    the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-
    middle attackers to spoof SSL servers via a CN= string in a field in the distinguished name (DN) of a
    certificate, as demonstrated by the foo,CN=www.apache.org string in the O field. (CVE-2014-3577)

  - http/conn/ssl/AbstractVerifier.java in Apache Commons HttpClient before 4.2.3 does not properly verify
    that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field
    of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via a certificate
    with a subject that specifies a common name in a field that is not the CN field. NOTE: this issue exists
    because of an incomplete fix for CVE-2012-5783. (CVE-2012-6153)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6453091");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.20, 9.0.5.8, or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fixes PH34501 and PH94944.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['version'], app);

if ('PH34501' >< app_info['Fixes'] && 'PH34944' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var fix = 'Interim Fixes PH34501 and PH34944';
var constraints = [
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_display':fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.19', 'fixed_display':'8.5.5.20 or ' + fix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.5.7', 'fixed_display':'9.0.5.8 or ' + fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
