
##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:2731. The text
# itself is copyright (C) Red Hat, Inc.
##



include('compat.inc');

if (description)
{
  script_id(151843);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");

  script_cve_id("CVE-2021-3347", "CVE-2021-33034", "CVE-2021-33909");
  script_xref(name:"RHSA", value:"2021:2731");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"RHEL 7 : kpatch-patch (RHSA-2021:2731)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:2731 advisory.

  - kernel: use-after-free in net/bluetooth/hci_event.c when destroying an hci_chan (CVE-2021-33034)

  - kernel: Use after free via PI futex state (CVE-2021-3347)

  - kernel: size_t-to-int conversion vulnerability in the filesystem layer (CVE-2021-33909)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3347");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33034");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1961305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1970273");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3347");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:7.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_58_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_61_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_61_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_62_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_65_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_66_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_70_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_72_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-957_76_1");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.6')) audit(AUDIT_OS_NOT, 'Red Hat 7.6', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

repositories = {
    'rhel_e4s_7_6_server': [
      'rhel-7-server-aus-debug-rpms',
      'rhel-7-server-aus-optional-debug-rpms',
      'rhel-7-server-aus-optional-rpms',
      'rhel-7-server-aus-optional-source-rpms',
      'rhel-7-server-aus-rpms',
      'rhel-7-server-aus-source-rpms',
      'rhel-7-server-e4s-debug-rpms',
      'rhel-7-server-e4s-debug-rpms__7_DOT_6__x86_64',
      'rhel-7-server-e4s-optional-debug-rpms',
      'rhel-7-server-e4s-optional-debug-rpms__7_DOT_6__x86_64',
      'rhel-7-server-e4s-optional-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-e4s-optional-rpms',
      'rhel-7-server-e4s-optional-rpms__7_DOT_6__x86_64',
      'rhel-7-server-e4s-optional-rpms__7_DOT_7__x86_64',
      'rhel-7-server-e4s-optional-source-rpms',
      'rhel-7-server-e4s-optional-source-rpms__7_DOT_6__x86_64',
      'rhel-7-server-e4s-optional-source-rpms__7_DOT_7__x86_64',
      'rhel-7-server-e4s-rpms',
      'rhel-7-server-e4s-rpms__7_DOT_6__x86_64',
      'rhel-7-server-e4s-source-rpms',
      'rhel-7-server-e4s-source-rpms__7_DOT_6__x86_64',
      'rhel-7-server-tus-debug-rpms',
      'rhel-7-server-tus-optional-debug-rpms',
      'rhel-7-server-tus-optional-rpms',
      'rhel-7-server-tus-optional-source-rpms',
      'rhel-7-server-tus-source-rpms',
      'rhel-ha-for-rhel-7-server-e4s-debug-rpms',
      'rhel-ha-for-rhel-7-server-e4s-debug-rpms__7_DOT_6__x86_64',
      'rhel-ha-for-rhel-7-server-e4s-debug-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-e4s-rpms',
      'rhel-ha-for-rhel-7-server-e4s-rpms__7_DOT_6__x86_64',
      'rhel-ha-for-rhel-7-server-e4s-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-e4s-source-rpms',
      'rhel-ha-for-rhel-7-server-e4s-source-rpms__7_DOT_6__x86_64',
      'rhel-ha-for-rhel-7-server-e4s-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_extras_sap_e4s_7_6': [
      'rhel-sap-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-for-rhel-7-server-e4s-debug-rpms__7_DOT_6__x86_64',
      'rhel-sap-for-rhel-7-server-e4s-rpms',
      'rhel-sap-for-rhel-7-server-e4s-rpms__7_DOT_6__x86_64',
      'rhel-sap-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-for-rhel-7-server-e4s-source-rpms__7_DOT_6__x86_64'
    ],
    'rhel_extras_sap_hana_e4s_7_6': [
      'rhel-sap-hana-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-debug-rpms__7_DOT_6__x86_64',
      'rhel-sap-hana-for-rhel-7-server-e4s-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-rpms__7_DOT_6__x86_64',
      'rhel-sap-hana-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-source-rpms__7_DOT_6__x86_64'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || empty_or_null(repo_sets)) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

kernel_live_checks = {
    '3.10.0-957.58.2.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_58_2-1-4.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.61.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_61_1-1-4.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.61.2.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_61_2-1-4.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.62.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_62_1-1-4.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.65.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_65_1-1-4.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.66.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_66_1-1-4.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.70.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_70_1-1-3.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.72.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_72_1-1-1.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']},
    '3.10.0-957.76.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-957_76_1-1-1.el7', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_7_6_server', 'rhel_extras_sap_e4s_7_6', 'rhel_extras_sap_hana_e4s_7_6']}
};

kpatch_details = kernel_live_checks[uname_r];
if (empty_or_null(kpatch_details)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

reference = NULL;
release = NULL;
sp = NULL;
cpu = NULL;
el_string = NULL;
rpm_spec_vers_cmp = NULL;
epoch = NULL;
allowmaj = NULL;
repo_list = NULL;
if (!empty_or_null(kpatch_details['repo_list'])) repo_list = kpatch_details['repo_list'];
if (!empty_or_null(kpatch_details['reference'])) reference = kpatch_details['reference'];
if (!empty_or_null(kpatch_details['release'])) release = 'RHEL' + kpatch_details['release'];
if (!empty_or_null(kpatch_details['sp'])) sp = kpatch_details['sp'];
if (!empty_or_null(kpatch_details['cpu'])) cpu = kpatch_details['cpu'];
if (!empty_or_null(kpatch_details['el_string'])) el_string = kpatch_details['el_string'];
if (!empty_or_null(kpatch_details['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = kpatch_details['rpm_spec_vers_cmp'];
if (!empty_or_null(kpatch_details['epoch'])) epoch = kpatch_details['epoch'];
if (!empty_or_null(kpatch_details['allowmaj'])) allowmaj = kpatch_details['allowmaj'];
if (reference && release) {
  repocheck = rhel_decide_repo_check(repo_list:repo_list, repo_sets:repo_sets);
  if (repocheck && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpatch-patch-3_10_0-957_58_2 / kpatch-patch-3_10_0-957_61_1 / etc');
}
