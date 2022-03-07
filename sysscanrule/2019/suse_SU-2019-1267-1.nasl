#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1267-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125246);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/17  9:44:15");

  script_cve_id("CVE-2019-11023");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : graphviz (SUSE-SU-2019:1267-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for graphviz fixes the following issues :

Security issue fixed :

CVE-2019-11023: Fixed a denial of service vulnerability, which was
caused by a NULL pointer dereference in agroot() (bsc#1132091).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11023/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191267-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-1267=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2019-1267=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1267=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-1267=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1267=1

SUSE Linux Enterprise High Availability 15:zypper in -t patch
SUSE-SLE-Product-HA-15-2019-1267=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-gvedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-gvedit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-plugins-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-smyrna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-smyrna-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphviz-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgraphviz6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgraphviz6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-tcl-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-tcl-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-gnome-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-gnome-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-doc-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-gnome-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-gnome-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-guile-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-guile-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-gvedit-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-gvedit-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-java-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-java-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-lua-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-lua-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-php-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-php-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-ruby-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-ruby-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-smyrna-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-smyrna-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-addons-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-perl-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-perl-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-devel-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-plugins-core-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"graphviz-plugins-core-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgraphviz6-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgraphviz6-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-addons-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-addons-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-gnome-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-gnome-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-addons-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-addons-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-doc-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-gnome-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-gnome-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-guile-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-guile-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-gvedit-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-gvedit-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-java-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-java-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-lua-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-lua-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-php-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-php-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-ruby-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-ruby-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-smyrna-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-smyrna-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-addons-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-addons-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-perl-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-perl-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-debugsource-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-devel-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-plugins-core-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"graphviz-plugins-core-debuginfo-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgraphviz6-2.40.1-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgraphviz6-debuginfo-2.40.1-6.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz");
}
