##
# 
##

include('compat.inc');

if (description)
{
  script_id(144050);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-17527");
  script_xref(name:"IAVA", value:"2020-A-0570");

  script_name(english:"Apache Tomcat 9.x < 9.0.40 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is 9.x prior to 9.0.40. It is, therefore, affected by an 
information disclosure vulnerability in its HTTP header functionality. An unauthenticated, remote attacker can exploit 
this, by sending specially crafted HTTP requests, to disclose potentially sensitive information from other requests.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13c2f9e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.40 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(
  min:'9.0.0-M1',
  fixed:'9.0.40',
  severity:SECURITY_WARNING,
  granularity_regex: "^9(\.0)?$"
);
