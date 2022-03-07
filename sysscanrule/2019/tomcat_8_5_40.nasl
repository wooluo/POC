#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124063);
  script_version("1.7");
  script_cvs_date("Date: 2019/07/03 12:01:42");

  script_cve_id("CVE-2019-0221", "CVE-2019-0232");
  script_bugtraq_id(107906);
  script_xref(name:"IAVB", value:"2019-B-0048");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.40 Remote Code Execution Vulnerability (Windows)");
  script_summary(english:"Checks the version of Apache Tomcat.");
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows Apache Tomcat server is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote Windows host is prior to 8.5.40. It is, therefore, affected by a remote
code execution vulnerability due to a bug in the way the JRE passes command line arguments to Windows. An 
unauthenticated, remote attacker can exploit this to execute arbitrary commands. 
Additionally, it is affected by a cross-site (XSS) scripting vulnerability as the SSI printenv command echoes user
provided data without proper escaping.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/tomcat/commit/5bc4e6d");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.40
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0232");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat", "Host/OS");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("tomcat_version.inc");

# Vuln only on Windows
os = get_kb_item_or_exit('Host/OS');
if ('Windows' >!< os) audit(AUDIT_OS_NOT, 'Windows', os);

conf = get_kb_item('Host/OS/Confidence');
if ((conf <= 70) && (report_paranoia < 2 )) 
{
  exit(1, 'Can\'t determine the host\'s OS with sufficient confidence and \'show potential false alarms\' is not enabled.');
}
tomcat_check_version(fixed: '8.5.40', min:'8.5.0', severity:SECURITY_HOLE, granularity_regex: "^8(\.5)?$", xss:TRUE);
