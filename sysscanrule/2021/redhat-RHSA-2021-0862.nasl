##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:0862. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147833);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id("CVE-2020-28374", "CVE-2020-29661");
  script_xref(name:"RHSA", value:"2021:0862");

  script_name(english:"RHEL 7 : kpatch-patch (RHSA-2021:0862)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:0862 advisory.

  - kernel: SCSI target (LIO) write to any block on ILO backstore (CVE-2020-28374)

  - kernel: locking issue in drivers/tty/tty_jobctrl.c can lead to an use-after-free (CVE-2020-29661)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/667.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:0862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1899804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1906525");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29661");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 416, 667);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1160_11_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1160_15_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1160_2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1160_2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1160_6_1");
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

uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

repositories = {
    'enterprise_linux_7_client': [
      'rhel-7-desktop-debug-rpms',
      'rhel-7-desktop-fastrack-debug-rpms',
      'rhel-7-desktop-fastrack-rpms',
      'rhel-7-desktop-fastrack-source-rpms',
      'rhel-7-desktop-optional-debug-rpms',
      'rhel-7-desktop-optional-fastrack-debug-rpms',
      'rhel-7-desktop-optional-fastrack-rpms',
      'rhel-7-desktop-optional-fastrack-source-rpms',
      'rhel-7-desktop-optional-rpms',
      'rhel-7-desktop-optional-source-rpms',
      'rhel-7-desktop-rpms',
      'rhel-7-desktop-source-rpms'
    ],
    'enterprise_linux_7_computenode': [
      'rhel-7-for-hpc-node-fastrack-debug-rpms',
      'rhel-7-for-hpc-node-fastrack-rpms',
      'rhel-7-for-hpc-node-fastrack-source-rpms',
      'rhel-7-for-hpc-node-optional-fastrack-debug-rpms',
      'rhel-7-for-hpc-node-optional-fastrack-rpms',
      'rhel-7-for-hpc-node-optional-fastrack-source-rpms',
      'rhel-7-hpc-node-debug-rpms',
      'rhel-7-hpc-node-optional-debug-rpms',
      'rhel-7-hpc-node-optional-rpms',
      'rhel-7-hpc-node-optional-source-rpms',
      'rhel-7-hpc-node-rpms',
      'rhel-7-hpc-node-source-rpms'
    ],
    'enterprise_linux_7_server': [
      'rhel-7-server-debug-rpms',
      'rhel-7-server-fastrack-debug-rpms',
      'rhel-7-server-fastrack-rpms',
      'rhel-7-server-fastrack-source-rpms',
      'rhel-7-server-optional-debug-rpms',
      'rhel-7-server-optional-fastrack-debug-rpms',
      'rhel-7-server-optional-fastrack-rpms',
      'rhel-7-server-optional-fastrack-source-rpms',
      'rhel-7-server-optional-rpms',
      'rhel-7-server-optional-source-rpms',
      'rhel-7-server-rpms',
      'rhel-7-server-source-rpms',
      'rhel-ha-for-rhel-7-server-debug-rpms',
      'rhel-ha-for-rhel-7-server-rpms',
      'rhel-ha-for-rhel-7-server-source-rpms',
      'rhel-rs-for-rhel-7-server-debug-rpms',
      'rhel-rs-for-rhel-7-server-rpms',
      'rhel-rs-for-rhel-7-server-source-rpms'
    ],
    'enterprise_linux_7_workstation': [
      'rhel-7-workstation-debug-rpms',
      'rhel-7-workstation-fastrack-debug-rpms',
      'rhel-7-workstation-fastrack-rpms',
      'rhel-7-workstation-fastrack-source-rpms',
      'rhel-7-workstation-optional-debug-rpms',
      'rhel-7-workstation-optional-fastrack-debug-rpms',
      'rhel-7-workstation-optional-fastrack-rpms',
      'rhel-7-workstation-optional-fastrack-source-rpms',
      'rhel-7-workstation-optional-rpms',
      'rhel-7-workstation-optional-source-rpms',
      'rhel-7-workstation-rpms',
      'rhel-7-workstation-source-rpms'
    ],
    'rhel_extras_7': [
      'rhel-7-desktop-supplementary-rpms',
      'rhel-7-desktop-supplementary-source-rpms',
      'rhel-7-for-hpc-node-supplementary-rpms',
      'rhel-7-for-hpc-node-supplementary-source-rpms',
      'rhel-7-hpc-node-eus-supplementary-rpms',
      'rhel-7-server-eus-supplementary-rpms',
      'rhel-7-server-supplementary-rpms',
      'rhel-7-server-supplementary-source-rpms',
      'rhel-7-workstation-supplementary-rpms',
      'rhel-7-workstation-supplementary-source-rpms'
    ],
    'rhel_extras_oracle_java_7': [
      'rhel-7-desktop-restricted-maintenance-oracle-java-rpms',
      'rhel-7-for-hpc-node-restricted-maintenance-oracle-java-rpms',
      'rhel-7-hpc-node-eus-restricted-maintenance-oracle-java-rpms',
      'rhel-7-server-eus-restricted-maintenance-oracle-java-rpms',
      'rhel-7-server-eus-restricted-maintenance-oracle-java-source-rpms',
      'rhel-7-server-restricted-maintenance-oracle-java-rpms',
      'rhel-7-workstation-restricted-maintenance-oracle-java-rpms'
    ],
    'rhel_extras_rt_7': [
      'rhel-7-server-nfv-debug-rpms',
      'rhel-7-server-nfv-rpms',
      'rhel-7-server-nfv-source-rpms',
      'rhel-7-server-rt-debug-rpms',
      'rhel-7-server-rt-rpms',
      'rhel-7-server-rt-source-rpms'
    ],
    'rhel_extras_sap_7': [
      'rhel-sap-for-rhel-7-server-debug-rpms',
      'rhel-sap-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-for-rhel-7-server-e4s-rpms',
      'rhel-sap-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-for-rhel-7-server-eus-debug-rpms',
      'rhel-sap-for-rhel-7-server-eus-rpms',
      'rhel-sap-for-rhel-7-server-eus-source-rpms',
      'rhel-sap-for-rhel-7-server-rpms',
      'rhel-sap-for-rhel-7-server-source-rpms'
    ],
    'rhel_extras_sap_hana_7': [
      'rhel-sap-hana-for-rhel-7-server-debug-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-hana-for-rhel-7-server-eus-debug-rpms',
      'rhel-sap-hana-for-rhel-7-server-eus-rpms',
      'rhel-sap-hana-for-rhel-7-server-eus-source-rpms',
      'rhel-sap-hana-for-rhel-7-server-rpms',
      'rhel-sap-hana-for-rhel-7-server-source-rpms'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

kernel_live_checks = {
    '3.10.0-1160.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1160-1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    '3.10.0-1160.11.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1160_11_1-1-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    '3.10.0-1160.15.2.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1160_15_2-1-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    '3.10.0-1160.2.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1160_2_1-1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    '3.10.0-1160.2.2.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1160_2_2-1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    '3.10.0-1160.6.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1160_6_1-1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpatch-patch-3_10_0-1160 / kpatch-patch-3_10_0-1160_11_1 / etc');
}
