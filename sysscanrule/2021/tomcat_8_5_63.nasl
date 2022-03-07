##
# 
##

include('compat.inc');

if (description)
{
  script_id(147019);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/04");

  script_cve_id("CVE-2021-25122", "CVE-2021-25329");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.63 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.63. It is, therefore, affected by multiple
vulnerabilities as referenced in the vendor advisory.

  - When responding to new h2c connection requests, Apache Tomcat versions 10.0.0-M1 to 10.0.0, 9.0.0.M1 to 9.0.41 
    and 8.5.0 to 8.5.61 could duplicate request headers and a limited amount of request body from one request to 
    another meaning user A and user B could both see the results of user A's request. (CVE-2021-25122)

  - When using Apache Tomcat 10.0.0-M1 to 10.0.0, 9.0.0.M1 to 9.0.41, 8.5.0 to 8.5.61 or 7.0.0. to 7.0.107 with a 
    configuration edge case that was highly unlikely to be used, the Tomcat instance was still vulnerable to 
    CVE-2020-9494. Note that both the previously published prerequisites for CVE-2020-9484 and the previously 
    published mitigations for CVE-2020-9484 also apply to this issue. (CVE-2021-25329)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/93f0cc403a9210d469afc2bd9cf03ab3251c6f35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6278e74");
  # https://github.com/apache/tomcat/commit/bb0e7c1e0d737a0de7d794572517bce0e91d30fa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0be223a3");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.63
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15b6baad");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.63 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25329");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '8.5.63', min:'8.5.0', severity:SECURITY_WARNING, granularity_regex: "^8(\.5)?$");
