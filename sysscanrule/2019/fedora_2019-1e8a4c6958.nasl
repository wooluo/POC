#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-1e8a4c6958.
#

include("compat.inc");

if (description)
{
  script_id(124284);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/25  9:51:46");

  script_cve_id("CVE-2019-9500");
  script_xref(name:"FEDORA", value:"2019-1e8a4c6958");

  script_name(english:"Fedora 29 : kernel / kernel-headers / kernel-tools (2019-1e8a4c6958)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The 5.0.9 update contains a number of important fixes across the tree

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-1e8a4c6958"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kernel, kernel-headers and / or kernel-tools
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-9500");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for FEDORA-2019-1e8a4c6958");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

flag = 0;
if (rpm_check(release:"FC29", reference:"kernel-5.0.9-200.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"kernel-headers-5.0.9-200.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"kernel-tools-5.0.9-200.fc29")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-headers / kernel-tools");
}
