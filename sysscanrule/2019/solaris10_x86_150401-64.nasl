#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(121184);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id("CVE-2019-2544");

  script_name(english:"Solaris 10 (x86) : 150401-64");
  script_summary(english:"Check for patch 150401-64");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 150401-64"
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
of Oracle Solaris accessible data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/150401-64"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 150401-64");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:127981");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142008");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142047");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142333");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:144312");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:144541");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146448");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146809");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146839");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146849");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147698");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148175");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148232");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148554");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148558");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148678");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148722");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148767");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148876");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149313");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149503");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149617");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149637");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149641");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149643");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149649");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149730");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150116");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150154");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150170");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150301");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150385");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150401");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150528");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150628");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150630");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150636");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150757");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150761");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151150");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151426");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

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
if (package_arch != "i386") audit(AUDIT_ARCH_NOT, "i386", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWdcar", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWfss", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWipoib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWlxr", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWmptsas", version:"11.10.0,REV=2009.07.13.23.13") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWpkcs11kms", version:"11.10.0,REV=2011.04.20.04.51") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWudfr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150401-64", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWarc / SUNWarcr / SUNWbtool / SUNWcakr / SUNWckr / SUNWcpc / etc");
}
