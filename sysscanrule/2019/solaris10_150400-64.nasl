#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(121178);
  script_version("1.7");
  script_cvs_date("Date: 2019/04/22  9:47:14");

  script_cve_id("CVE-2019-2544", "CVE-2019-2545");

  script_name(english:"Solaris 10 (sparc) : 150400-64");
  script_summary(english:"Check for patch 150400-64");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 150400-64"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Oracle Solaris component of Oracle Sun Systems
Products Suite (subcomponent: Kernel). Supported versions that are
affected are 10 and 11. Easily exploitable vulnerability allows
unauthenticated attacker with logon to the infrastructure where Oracle
Solaris executes to compromise Oracle Solaris. Successful attacks of
this vulnerability can result in unauthorized read access to a subset
of Oracle Solaris accessible data.

Vulnerability in the Oracle Solaris component of Oracle Sun Systems
Products Suite (subcomponent: LDoms IO). Supported versions that are
affected are 10 and 11. Easily exploitable vulnerability allows
unauthenticated attacker with logon to the infrastructure where Oracle
Solaris executes to compromise Oracle Solaris. Successful attacks of
this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Oracle Solaris."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/150400-64"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 150400-64");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:122255");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:127980");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137048");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139944");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142007");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142332");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:144540");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146808");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146838");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146848");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147697");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148174");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148231");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148338");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148553");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148557");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148721");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148730");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148766");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148875");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149502");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149616");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149640");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149642");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149648");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149718");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149729");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150108");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150115");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150125");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150300");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150307");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150311");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150400");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150527");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150531");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150532");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150541");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150627");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150629");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150756");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150760");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150840");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150841");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151145");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151149");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151425");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151608");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:152367");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:152530");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:152539");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

showrev = get_kb_item("Host/Solaris/showrev");
if (empty_or_null(showrev)) audit(AUDIT_OS_NOT, "Solaris");
os_ver = pregmatch(pattern:"Release: (\d+.(\d+))", string:showrev);
if (empty_or_null(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Solaris");
full_ver = os_ver[1];
os_level = os_ver[2];
if (full_ver != "5.10") audit(AUDIT_OS_NOT, "Solaris 10", "Solaris " + os_level);
package_arch = pregmatch(pattern:"Application architecture: (\w+)", string:showrev);
if (empty_or_null(package_arch)) audit(AUDIT_UNKNOWN_ARCH);
package_arch = package_arch[1];
if (package_arch != "sparc") audit(AUDIT_ARCH_NOT, "sparc", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"FJSVpiclu", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWdcar", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWdrcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWefcl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWfss", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.09.15.00.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWiopc", version:"11.10.0,REV=2006.07.11.11.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWipoib", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.08.04.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWmptsas", version:"11.10.0,REV=2009.07.14.02.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWn2cp", version:"11.10.0,REV=2007.07.08.21.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWpd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWpdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWpkcs11kms", version:"11.10.0,REV=2011.06.03.09.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWs8brandr", version:"11.10.0,REV=2007.10.08.16.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWs8brandu", version:"11.10.0,REV=2007.10.08.16.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWs9brandr", version:"11.10.0,REV=2008.04.24.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWs9brandu", version:"11.10.0,REV=2008.04.24.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWssad", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWudfr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-64", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;

if (flag) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : solaris_get_report()
  );
} else {
  patch_fix = solaris_patch_fix_get();
  if (!empty_or_null(patch_fix)) audit(AUDIT_PATCH_INSTALLED, patch_fix, "Solaris 10");
  tested = solaris_pkg_tests_get();
  if (!empty_or_null(tested)) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "FJSVhea / FJSVmdb / FJSVmdbr / FJSVpiclu / SUNWarc / SUNWarcr / etc");
}
