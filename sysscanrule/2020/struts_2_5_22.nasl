#
# 
#

include('compat.inc');

if (description)
{
  script_id(139607);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id("CVE-2019-0230", "CVE-2019-0233");

  script_name(english:"Apache Struts 2.x <= 2.5.20 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Apache Struts installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts installed on the remote host is 2.x prior or equal to 2.5.20. It is, therefore,
affected by multiple vulnerabilities:

  - The Apache Struts frameworks, when forced, performs double evaluation of attributes' values assigned to
    certain tags attributes such as id so it is possible to pass in a value that will be evaluated again when
    a tag's attributes will be rendered. With a carefully crafted request, this can lead to Remote Code
    Execution (RCE).The problem only applies when forcing OGNL evaluation inside a Struts tag attribute, when
    the expression to evaluate references raw, unvalidated input that an attacker is able to directly modify
    by crafting a corresponding request.Example:List available EmployeesIf an attacker is able to modify the
    skillName attribute in a request such that a raw OGNL expression gets passed to the skillName property
    without further validation, the provided OGNL expression contained in the skillName attribute gets
    evaluated when the tag is rendered as a result of the request.The opportunity for using double evaluation
    is by design in Struts since 2.0.0 and a useful tool when done right, which most notably means only
    referencing validated values in the given expression. However, when referencing unvalidated user input in
    the expression, malicious code can get injected. In an ongoing effort, the Struts framework includes
    mitigations for limiting the impact of injected expressions, but Struts before 2.5.22 left an attack
    vector open which is addressed by this report. This issue is similar to: S2-029 and S2-036. (CVE-2019-0230)

  - When a file upload is performed to an Action that exposes the file with a getter, an attacker may
    manipulate the request such that the working copy of the uploaded file is set to read-only. As a result,
    subsequent actions on the file will fail with an error. It might also be possible to set the Servlet
    container's temp directory to read only, such that subsequent upload actions will fail. In Struts prior
    to 2.5.22, stack-accessible values (e.g. Action properties) of type java.io.File and java.nio.File as well
    as other classes from these standard library packages are not properly protected by the framework to deny
    access to potentially harmful underlying properties. (CVE-2019-0233)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-059");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-060");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.5.22 or later or apply the workarounds as referenced in in the vendor security
bulletins.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0230");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

win_local = FALSE;
os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;

app_info = vcf::get_app_info(app:'Apache Struts', win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.5.20', 'fixed_version' : '2.5.22' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

