include("compat.inc");

if (description)
{
  script_id(51799010);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/12 23:20:21 $");

  script_cve_id("CVE-2016-9299");
  script_bugtraq_id(94281);

  script_name(english:"Jenkins Remote Code Excute (CVE-2016-9299)");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"The remoting module in Jenkins before 2.32 and LTS before 2.19.3 allows remote attackers to execute arbitrary code via a crafted serialized Java object, which triggers an LDAP query to a third-party server.");
  script_set_attribute(attribute:"description", value:
"The remoting module in Jenkins before 2.32 and LTS before 2.19.3 allows remote attackers to execute arbitrary code via a crafted serialized Java object, which triggers an LDAP query to a third-party server.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/jenkins-security-advisory-2016-11-16");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.32 or later, Jenkins LTS to version
2.19.3 or later.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"risk_factor", value: "High" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/Jenkins");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = -1;
if(isnull(get_kb_item("www/Jenkins/8080/Installed")))
{
	ports = get_kb_list("Services/www");
	if(isnull(ports)) audit(AUDIT_INST_VER_NOT_VULN, appname);
	foreach p (ports)
	{
		if(!isnull(get_kb_item("www/Jenkins/" + p + "/Installed")))
		{
			port = p;
			break;
		}
	}
}
else
{
	port = 8080;
}
get_kb_item_or_exit("www/Jenkins/" + p + "/Installed");
url = build_url(qs:'/', port:port);

version = '';
fix = '';
if (get_kb_item("www/Jenkins/"+port+"/is_LTS") )
{
  appname = "Jenkins Open Source LTS";
  fix = '2.19.3';
}
else
{
  appname = "Jenkins Open Source";
  fix = '2.32';
}

version = get_kb_item("www/Jenkins/" + port + "/JenkinsVersion");
if (version == 'unknown')
{
  audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);
}

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL           : ' + url +
    '\n  Product       : ' + appname +
    '\n  Version       : ' + version +
    '\n  Fixed version : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xss:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
