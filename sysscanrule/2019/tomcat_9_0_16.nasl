#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126312);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/27 16:47:34");

  script_cve_id("CVE-2019-0199");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.16 a vulnerability");
  script_summary(english:"Checks the version of Apache_Tomcat.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.16.
It is, therefore, affected by a vulnerability as referenced in the
fixed_in_apache_tomcat_9.0.16_security-9 advisory.

  - The HTTP/2 implementation accepted streams with
    excessive numbers of SETTINGS frames and also permitted
    clients to keep streams open without reading/writing
    request/response data. By keeping streams open for
    requests that utilised the Servlet API's blocking I/O,
    clients were able to cause server-side threads to block
    eventually leading to thread exhaustion and a DoS.
    (CVE-2019-0199)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852698");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852699");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852700");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852701");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852702");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852703");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852704");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852705");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852706");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/tomcat/commit/a1cb1ac");
  # http://tomcat.apache.org/tomcat-9.0-doc/changelog.html
  # http://mail-archives.apache.org/mod_mbox/www-announce/201902.mbox/%3Cff960410-b09c-32b4-eae6-5d5ed01df1bd@apache.org%3E
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0199");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
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

tomcat_check_version(fixed: '9.0.16', min:'9.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^9(\.0)?$");
