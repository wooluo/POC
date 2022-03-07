#
# 
#

include('compat.inc');

if (description)
{
  script_id(136807);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/27");

  script_cve_id("CVE-2020-9484");

  script_name(english:"Apache Tomcat 8.0.0 < 8.5.55 Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to
7.0.104. It is, therefore, affected by a remote code execution
vulnerability as referenced in the fixed_in_apache_tomcat_8.5.55_security-8
advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.55
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9502c510");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '8.5.55', min:'8.0.0', severity:SECURITY_WARNING, granularity_regex: "^8(\.5)?$");
