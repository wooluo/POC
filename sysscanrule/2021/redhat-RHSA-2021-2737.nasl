
##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:2737. The text
# itself is copyright (C) Red Hat, Inc.
##



include('compat.inc');

if (description)
{
  script_id(151929);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/30");

  script_cve_id("CVE-2021-33034", "CVE-2021-33909");
  script_xref(name:"RHSA", value:"2021:2737");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"RHEL 7 : RHV-H security update (redhat-virtualization-host) 4.3.17 (Important) (RHSA-2021:2737)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2021:2737 advisory.

  - kernel: use-after-free in net/bluetooth/hci_event.c when destroying an hci_chan (CVE-2021-33034)

  - kernel: size_t-to-int conversion vulnerability in the filesystem layer (CVE-2021-33909)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33034");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1961305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1970273");
  script_set_attribute(attribute:"solution", value:
"Update the affected redhat-virtualization-host-image-update package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33909");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Red Hat' >!< release) audit(AUDIT_OS_NOT, 'Red Hat');
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

repositories = {
    'enterprise_linux_7_hypervisor': [
      'rhel-7-server-rhev-mgmt-agent-debug-rpms',
      'rhel-7-server-rhev-mgmt-agent-els-debug-rpms',
      'rhel-7-server-rhev-mgmt-agent-els-rpms',
      'rhel-7-server-rhev-mgmt-agent-els-source-rpms',
      'rhel-7-server-rhev-mgmt-agent-rpms',
      'rhel-7-server-rhev-mgmt-agent-source-rpms',
      'rhel-7-server-rhevh-els-rpms',
      'rhel-7-server-rhevh-els-source-rpms',
      'rhel-7-server-rhevh-rpms',
      'rhel-7-server-rhevh-source-rpms',
      'rhel-7-server-rhv-4-manager-tools-debug-rpms',
      'rhel-7-server-rhv-4-manager-tools-rpms',
      'rhel-7-server-rhv-4-manager-tools-source-rpms',
      'rhel-7-server-rhv-4-mgmt-agent-debug-rpms',
      'rhel-7-server-rhv-4-mgmt-agent-rpms',
      'rhel-7-server-rhv-4-mgmt-agent-source-rpms',
      'rhel-7-server-rhv-4-tools-debug-rpms',
      'rhel-7-server-rhv-4-tools-rpms',
      'rhel-7-server-rhv-4-tools-source-rpms',
      'rhel-7-server-rhv-4.2-mgmt-agent-eus-debug-rpms',
      'rhel-7-server-rhv-4.2-mgmt-agent-eus-rpms',
      'rhel-7-server-rhv-4.2-mgmt-agent-eus-source-rpms',
      'rhel-7-server-rhv-4.3-mgmt-agent-eus-rpms',
      'rhel-7-server-rhvh-4-build-debug-rpms',
      'rhel-7-server-rhvh-4-build-rpms',
      'rhel-7-server-rhvh-4-build-source-rpms',
      'rhel-7-server-rhvh-4-debug-rpms',
      'rhel-7-server-rhvh-4-rpms',
      'rhel-7-server-rhvh-4-source-rpms',
      'rhel-7-server-rhvh-4.2-build-eus-rpms',
      'rhel-7-server-rhvh-4.2-build-eus-source-rpms',
      'rhel-7-server-rhvh-4.2-eus-debug-rpms',
      'rhel-7-server-rhvh-4.2-eus-rpms',
      'rhel-7-server-rhvh-4.2-eus-source-rpms',
      'rhel-7-server-rhvh-4.3-build-eus-rpms',
      'rhel-7-server-rhvh-4.3-build-eus-source-rpms',
      'rhel-7-server-rhvh-4.3-eus-rpms',
      'rhel-7-server-rhvh-4.3-eus-source-rpms'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

pkgs = [
    {'reference':'redhat-virtualization-host-image-update-4.3.17-20210713.0.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_hypervisor']}
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
  repo_list = NULL;
  if (!empty_or_null(package_array['repo_list'])) repo_list = package_array['repo_list'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    repocheck = rhel_decide_repo_check(repo_list:repo_list, repo_sets:repo_sets);
    if (repocheck && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  if (empty_or_null(repo_sets)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redhat-virtualization-host-image-update');
}
