#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2019-195-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126685);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/15 14:20:21");

  script_cve_id("CVE-2016-3189", "CVE-2019-12900");
  script_xref(name:"SSA", value:"2019-195-01");

  script_name(english:"Slackware 14.0 / 14.1 / 14.2 / current : bzip2 (SSA:2019-195-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New bzip2 packages are available for Slackware 14.0, 14.1, 14.2, and
-current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2019&m=slackware-security.423144
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bzip2 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"14.0", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;

if (slackware_check(osver:"14.1", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;

if (slackware_check(osver:"14.2", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;

if (slackware_check(osver:"current", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"bzip2", pkgver:"1.0.8", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
