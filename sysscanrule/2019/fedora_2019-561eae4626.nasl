#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-561eae4626.
#

include("compat.inc");

if (description)
{
  script_id(123100);
  script_version("1.8");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2019-5754", "CVE-2019-5755", "CVE-2019-5756", "CVE-2019-5757", "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760", "CVE-2019-5761", "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764", "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768", "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5771", "CVE-2019-5772", "CVE-2019-5773", "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776", "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780", "CVE-2019-5781", "CVE-2019-5782", "CVE-2019-5784", "CVE-2019-5786", "CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790", "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794", "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798", "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5801", "CVE-2019-5802", "CVE-2019-5803", "CVE-2019-5804");
  script_xref(name:"FEDORA", value:"2019-561eae4626");

  script_name(english:"Fedora 29 : chromium (2019-561eae4626)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 73.0.3683.75. Fixes large bucket of CVEs.

CVE-2019-5754 CVE-2019-5782 CVE-2019-5755 CVE-2019-5756 CVE-2019-5757
CVE-2019-5758 CVE-2019-5759 CVE-2019-5760 CVE-2019-5761 CVE-2019-5762
CVE-2019-5763 CVE-2019-5764 CVE-2019-5765 CVE-2019-5766 CVE-2019-5767
CVE-2019-5768 CVE-2019-5769 CVE-2019-5770 CVE-2019-5771 CVE-2019-5772
CVE-2019-5773 CVE-2019-5774 CVE-2019-5775 CVE-2019-5776 CVE-2019-5777
CVE-2019-5778 CVE-2019-5779 CVE-2019-5780 CVE-2019-5781 CVE-2019-5784
CVE-2019-5786 CVE-2019-5787 CVE-2019-5788 CVE-2019-5789 CVE-2019-5790
CVE-2019-5791 CVE-2019-5792 CVE-2019-5793 CVE-2019-5794 CVE-2019-5795
CVE-2019-5796 CVE-2019-5797 CVE-2019-5798 CVE-2019-5799 CVE-2019-5800
CVE-2019-5802 CVE-2019-5803

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-561eae4626"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Chrome 72.0.3626.119 FileReader UaF exploit for Windows 7 x86');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


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


flag = 0;
if (rpm_check(release:"FC29", reference:"chromium-73.0.3683.75-2.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
