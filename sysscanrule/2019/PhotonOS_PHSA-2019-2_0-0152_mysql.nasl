#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2019-2.0-0152. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(126216);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/25  6:49:04");

  script_cve_id(
    "CVE-2018-3123",
    "CVE-2018-3133",
    "CVE-2018-3137",
    "CVE-2018-3143",
    "CVE-2018-3144",
    "CVE-2018-3145",
    "CVE-2018-3155",
    "CVE-2018-3156",
    "CVE-2018-3161",
    "CVE-2018-3162",
    "CVE-2018-3170",
    "CVE-2018-3171",
    "CVE-2018-3173",
    "CVE-2018-3174",
    "CVE-2018-3182",
    "CVE-2018-3185",
    "CVE-2018-3186",
    "CVE-2018-3187",
    "CVE-2018-3195",
    "CVE-2018-3200",
    "CVE-2018-3203",
    "CVE-2018-3212",
    "CVE-2018-3247",
    "CVE-2018-3251",
    "CVE-2018-3276",
    "CVE-2018-3277",
    "CVE-2018-3278",
    "CVE-2018-3279",
    "CVE-2018-3280",
    "CVE-2018-3282",
    "CVE-2018-3283",
    "CVE-2018-3284",
    "CVE-2018-3285",
    "CVE-2018-3286",
    "CVE-2019-2420",
    "CVE-2019-2434",
    "CVE-2019-2455",
    "CVE-2019-2481",
    "CVE-2019-2482",
    "CVE-2019-2486",
    "CVE-2019-2503",
    "CVE-2019-2507",
    "CVE-2019-2510",
    "CVE-2019-2528",
    "CVE-2019-2529",
    "CVE-2019-2531",
    "CVE-2019-2532",
    "CVE-2019-2534",
    "CVE-2019-2537"
  );

  script_name(english:"Photon OS 2.0: Mysql PHSA-2019-2.0-0152");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the mysql package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-2-152.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3828");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/PhotonOS/release");
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, "PhotonOS");
if (release !~ "^VMware Photon (?:Linux|OS) 2\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 2.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

if (rpm_check(release:"PhotonOS-2.0", reference:"mysql-5.7.25-1.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"mysql-debuginfo-5.7.25-1.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"mysql-devel-5.7.25-1.ph2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}
