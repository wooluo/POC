##
# 
##

include('compat.inc');

if (description)
{
  script_id(147164);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2021-25122", "CVE-2021-25329");
  script_xref(name:"IAVA", value:"2021-A-0114");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.43 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.43. It is, therefore, affected by multiple
vulnerabilities as referenced in the vendor advisory.

  - An information disclosure vulnerability exists when responding to new h2c connection requests, Apache Tomcat 
    versions 9.0.0.M1 to 9.0.41 could duplicate request headers and a limited amount of request body from one request 
    to another meaning user A and user B could both see the results of user A's request. (CVE-2021-25122)

  - when using Apache Tomcat 10.0.0-M1 to 10.0.0, 9.0.0.M1 to 9.0.41, 8.5.0 to 8.5.61 or 7.0.0. to 7.0.107 with a 
    configuration edge case that was highly unlikely to be used, the Tomcat instance was still vulnerable to 
    CVE-2020-9494. Note that both the previously published prerequisites for CVE-2020-9484 and the previously 
    published mitigations for CVE-2020-9484 also apply to this issue. (CVE-2021-25329)

  - A remote code execution vulnerability via deserialization exists when using Apache Tomcat 9.0.0.M1 to 9.0.41 with a
    configuration edge case that was highly unlikely to be used, the Tomcat instance was still vulnerable to 
    CVE-2020-9494. Note that both the previously published prerequisites for CVE-2020-9484 and the previously published 
    mitigations for CVE-2020-9484 also apply to this issue. (CVE-2021-25329)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/4785433a226a20df6acbea49296e1ce7e23de453
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00b2f5b4");
  # https://github.com/apache/tomcat/commit/d47c20a776e8919eaca8da9390a32bc8bf8210b1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6d3f1a3");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.43
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7051ce31");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.43 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(min:'9.0.0-M1', fixed: '9.0.43', severity:SECURITY_WARNING, granularity_regex: "^9(\.0)?$");