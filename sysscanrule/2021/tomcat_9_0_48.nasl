
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152182);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/03");

  script_cve_id("CVE-2021-33037");
  script_xref(name:"IAVA", value:"2021-A-0303");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.48 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.48. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.48_security-9 advisory.

  - Apache Tomcat 10.0.0-M1 to 10.0.6, 9.0.0.M1 to 9.0.46 and 8.5.0 to 8.5.66 did not correctly parse the HTTP
    transfer-encoding request header in some circumstances leading to the possibility to request smuggling
    when used with a reverse proxy. Specifically: - Tomcat incorrectly ignored the transfer encoding header if
    the client declared it would only accept an HTTP/1.0 response; - Tomcat honoured the identify encoding;
    and - Tomcat did not ensure that, if present, the chunked encoding was the final encoding.
    (CVE-2021-33037)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/45d70a86a901cbd534f8f570bed2aec9f7f7b88e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3abdcc43");
  # https://github.com/apache/tomcat/commit/05f9e8b00f5d9251fcd3c95dcfd6cf84177f46c8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2af8a80");
  # https://github.com/apache/tomcat/commit/a2c3dc4c96168743ac0bab613709a5bbdaec41d0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8db985a");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.48
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19f14e83");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.48 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33037");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/03");

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

tomcat_check_version(fixed: '9.0.48', min:'9.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^9(\.0)?$");
