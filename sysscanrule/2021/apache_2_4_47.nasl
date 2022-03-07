##
# 
##



include('compat.inc');

if (description)
{
  script_id(150280);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id(
    "CVE-2019-17567",
    "CVE-2020-13938",
    "CVE-2020-13950",
    "CVE-2020-35452",
    "CVE-2021-26690",
    "CVE-2021-26691",
    "CVE-2021-30641"
  );
  script_xref(name:"IAVA", value:"2021-A-0259");

  script_name(english:"Apache 2.4.x < 2.4.47 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.47. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.47 changelog:

  - Unexpected <Location> section matching with 'MergeSlashes OFF' (CVE-2021-30641)

  - mod_auth_digest: possible stack overflow by one nul byte while validating the Digest nonce. (CVE-2020-35452)

  - mod_session: Fix possible crash due to NULL pointer dereference, which could be used to cause a Denial of Service
    with a malicious backend server and SessionHeader. (CVE-2021-26691)

  - mod_session: Fix possible crash due to NULL pointer dereference, which could be used to cause a Denial of Service.
    (CVE-2021-26690)

  - mod_proxy_http: Fix possible crash due to NULL pointer dereference, which could be used to cause a Denial of
    Service. (CVE-2020-13950)

  - Windows: Prevent local users from stopping the httpd process (CVE-2020-13938)

  - mod_proxy_wstunnel, mod_proxy_http: Handle Upgradable protocols end-to-end negotiation. (CVE-2019-17567)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://downloads.apache.org/httpd/CHANGES_2.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.47 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  # no modules list here since CVE-2021-30641 affects core httpd
  { 'min_version' : '2.4.0', 'fixed_version' : '2.4.47' }
];

vcf::apache_http_server::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

