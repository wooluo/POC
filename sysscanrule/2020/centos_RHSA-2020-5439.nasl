##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5439 and
# CentOS Errata and Security Advisory 2020:5439 respectively.
##

include('compat.inc');

if (description)
{
  script_id(144973);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2020-1472", "CVE-2020-14318", "CVE-2020-14323");
  script_xref(name:"RHSA", value:"2020:5439");

  script_name(english:"CentOS 7 : samba (CESA-2020:5439)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:5439 advisory.

  - samba: Missing handle permissions check in SMB1/2/3 ChangeNotify (CVE-2020-14318)

  - samba: Unprivileged user can crash winbind (CVE-2020-14323)

  - samba: Netlogon elevation of privilege vulnerability (Zerologon) (CVE-2020-1472)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2020-December/048217.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d69dc2e");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/170.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/266.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/287.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");
  script_cwe_id(170, 266, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'ctdb-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'ctdb-tests-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'libsmbclient-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'libsmbclient-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'libsmbclient-devel-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'libsmbclient-devel-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'libwbclient-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'libwbclient-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'libwbclient-devel-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'libwbclient-devel-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-client-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-client-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'samba-client-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-common-4.10.16-9.el7_9', 'sp':'9', 'release':'CentOS-7'},
    {'reference':'samba-common-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'samba-common-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-common-tools-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-dc-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-dc-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-devel-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'samba-devel-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-krb5-printing-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'samba-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-pidl-4.10.16-9.el7_9', 'sp':'9', 'release':'CentOS-7'},
    {'reference':'samba-python-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'samba-python-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-python-test-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-test-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-test-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'samba-test-libs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-vfs-glusterfs-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-winbind-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-winbind-clients-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-winbind-krb5-locator-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'samba-winbind-modules-4.10.16-9.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'samba-winbind-modules-4.10.16-9.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / ctdb-tests / libsmbclient / etc');
}
