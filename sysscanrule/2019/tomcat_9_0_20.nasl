#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126245);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/28 10:05:54");

  script_cve_id("CVE-2019-0199", "CVE-2019-10072");
  script_xref(name:"IAVB", value:"2019-B-0051");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.20 a vulnerability");
  script_summary(english:"Checks the version of Apache_Tomcat.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.20. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.20_security-9 advisory.

  - The fix for CVE-2019-0199 was incomplete and did not
    address HTTP/2 connection window exhaustion on write. By
    not sending WINDOW_UPDATE messages for the connection
    window (stream 0) clients were able to cause server-side
    threads to block eventually leading to thread exhaustion
    and a DoS. (CVE-2019-10072)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/tomcat/commit/7f748eb");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/tomcat/commit/ada725a");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0199");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_keys("installed_sw/Apache Tomcat", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '9.0.20', min:'9.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^9(\.0)?$");
