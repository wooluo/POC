#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126924);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id(
    "CVE-2019-2602",
    "CVE-2019-2684",
    "CVE-2019-2697",
    "CVE-2019-2698",
    "CVE-2019-10245"
  );
  script_bugtraq_id(
    107915,
    107917,
    107918,
    107922,
    108094
  );

  script_name(english:"AIX Java Advisory : java_apr2019_advisory.asc (April 2019 CPU)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities in the following subcomponents :

  - A flaw exists in Libraries that allows an unauthenticated, remote
   attacker to cause denial of service. (CVE-2019-2602)

  - A flaw exists in the RMI component that allows an unauthenticated,
    remote attacker to cause unspecified integrity impact.
    (CVE-2019-2684)

  - Flaws exist in the 2D component that allows an unauthenticated,
    remote attacker to take control of the system via unspecified
    means. (CVE-2019-2697, CVE-2019-2698)

  - A flaw exists in Eclipse OpenJ9 that allows an unauthenticated,
    remote attacker to cause denial of service. (CVE-2019-10245)");
  # https://aix.software.ibm.com/aix/efixes/security/java_apr2019_advisory.asc
  script_set_attribute(attribute:"see_also", value:"");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2697");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version", "Host/AIX/oslevelsp");

  exit(0);
}

include('aix.inc');
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') )
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit('Host/AIX/version');
if (
  oslevel != 'AIX-7.1' &&
  oslevel != 'AIX-7.2'
)
{
  oslevel = ereg_replace(string:oslevel, pattern:'-', replace:' ');
  audit(AUDIT_OS_NOT, 'AIX 7.1 / 7.2', oslevel);
}

oslevelcomplete = chomp(get_kb_item('Host/AIX/oslevelsp'));
if (empty_or_null(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, 'AIX');

if ( ! get_kb_item('Host/AIX/lslpp') ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

#Java7 7.0.0.645
if (aix_check_package(release:'7.1', package:'Java7.sdk', minpackagever:'7.0.0.0', maxpackagever:'7.0.0.644', fixpackagever:'7.0.0.645') > 0) flag++;
if (aix_check_package(release:'7.2', package:'Java7.sdk', minpackagever:'7.0.0.0', maxpackagever:'7.0.0.644', fixpackagever:'7.0.0.645') > 0) flag++;
if (aix_check_package(release:'7.1', package:'Java7_64.sdk', minpackagever:'7.0.0.0', maxpackagever:'7.0.0.644', fixpackagever:'7.0.0.645') > 0) flag++;
if (aix_check_package(release:'7.2', package:'Java7_64.sdk', minpackagever:'7.0.0.0', maxpackagever:'7.0.0.644', fixpackagever:'7.0.0.645') > 0) flag++;

#Java7.1 7.1.0.445
if (aix_check_package(release:'7.1', package:'Java7.sdk', minpackagever:'7.1.0.0', maxpackagever:'7.1.0.444', fixpackagever:'7.1.0.445') > 0) flag++;
if (aix_check_package(release:'7.2', package:'Java7.sdk', minpackagever:'7.1.0.0', maxpackagever:'7.1.0.444', fixpackagever:'7.1.0.445') > 0) flag++;
if (aix_check_package(release:'7.1', package:'Java7_64.sdk', minpackagever:'7.1.0.0', maxpackagever:'7.1.0.444', fixpackagever:'7.1.0.445') > 0) flag++;
if (aix_check_package(release:'7.2', package:'Java7_64.sdk', minpackagever:'7.1.0.0', maxpackagever:'7.1.0.444', fixpackagever:'7.1.0.445') > 0) flag++;

#Java8.0 8.0.0.537
if (aix_check_package(release:'7.1', package:'Java8.sdk', minpackagever:'8.0.0.0', maxpackagever:'8.0.0.536', fixpackagever:'8.0.0.537') > 0) flag++;
if (aix_check_package(release:'7.2', package:'Java8.sdk', minpackagever:'8.0.0.0', maxpackagever:'8.0.0.536', fixpackagever:'8.0.0.537') > 0) flag++;
if (aix_check_package(release:'7.1', package:'Java8_64.sdk', minpackagever:'8.0.0.0', maxpackagever:'8.0.0.536', fixpackagever:'8.0.0.537') > 0) flag++;
if (aix_check_package(release:'7.2', package:'Java8_64.sdk', minpackagever:'8.0.0.0', maxpackagever:'8.0.0.536', fixpackagever:'8.0.0.537') > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Java7 / Java8');
}
