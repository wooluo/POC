#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103329);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/10/12 16:44:11 $");

  script_cve_id("CVE-2017-12615", "CVE-2017-12616");
  script_bugtraq_id(100897, 100901);
  script_osvdb_id(114313, 114314);

  script_name(english:"Apache Tomcat 7.0.x < 7.0.81 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");
  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 7.0.x
prior to 7.0.81. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified vulnerability when running on Windows
    with HTTP PUTs enabled (e.g. via setting the readonly
    initialization parameter of the Default to false) makes
    it possible to upload a JSP file to the server via a
    specially crafted request. This JSP could then be
    requested and any code it contained would be
    executed by the server. (CVE-2017-12615, CVE-2017-12617)

  - When using a VirtualDirContext it was possible to bypass
    security constraints and/or view the source code of JSPs
    for resources served by the VirtualDirContext using a
    specially crafted request. (CVE-2017-12616)

Note that GizaNE has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.81
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.81 or later.

Note that the remote code execution issue was fixed in Apache Tomcat
7.0.80 but the release vote for the 7.0.81 release candidate did not
pass. Therefore, although users must download 7.0.81 to obtain a
version that includes the fix for this issue, version 7.0.80 is not
included in the list of affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

tomcat_check_version(fixed:"7.0.80", fixed_display:"7.0.81", min:"7.0", severity:SECURITY_HOLE, granularity_regex:"^7(\.0)?$");
