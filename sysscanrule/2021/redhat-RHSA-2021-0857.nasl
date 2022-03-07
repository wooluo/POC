##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:0857. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147827);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id(
    "CVE-2019-19532",
    "CVE-2020-0427",
    "CVE-2020-7053",
    "CVE-2020-14351",
    "CVE-2020-25211",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25705",
    "CVE-2020-28374",
    "CVE-2020-29661",
    "CVE-2021-20265"
  );
  script_xref(name:"RHSA", value:"2021:0857");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2021:0857)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:0857 advisory.

  - kernel: malicious USB devices can lead to multiple out-of-bounds write (CVE-2019-19532)

  - kernel: out-of-bounds reads in pinctrl subsystem. (CVE-2020-0427)

  - kernel: performance counters race condition use-after-free (CVE-2020-14351)

  - kernel: Local buffer overflow in ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c
    (CVE-2020-25211)

  - kernel: Geneve/IPsec traffic may be unencrypted between two Geneve endpoints (CVE-2020-25645)

  - kernel: use-after-free in read in vt_do_kdgkb_ioctl (CVE-2020-25656)

  - kernel: ICMP rate limiting can be used for DNS poisoning attack (CVE-2020-25705)

  - kernel: SCSI target (LIO) write to any block on ILO backstore (CVE-2020-28374)

  - kernel: locking issue in drivers/tty/tty_jobctrl.c can lead to an use-after-free (CVE-2020-29661)

  - kernel: use-after-free in i915_ppgtt_close in drivers/gpu/drm/i915/i915_gem_gtt.c (CVE-2020-7053)

  - kernel: increase slab leak leads to DoS (CVE-2021-20265)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/319.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/330.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/400.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/667.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19532");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0427");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7053");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25645");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25656");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25705");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20265");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:0857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1795624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1862849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1883988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1888726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1894579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1899804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1906525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1908827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1919893");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29661");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 200, 319, 330, 400, 416, 667);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

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

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2019-19532', 'CVE-2020-0427', 'CVE-2020-7053', 'CVE-2020-14351', 'CVE-2020-25211', 'CVE-2020-25645', 'CVE-2020-25656', 'CVE-2020-25705', 'CVE-2020-28374', 'CVE-2020-29661', 'CVE-2021-20265');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:0857');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'kernel-rt-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-debug-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-debug-devel-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-debug-kvm-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-devel-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-doc-3.10.0-1160.21.1.rt56.1158.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-kvm-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-trace-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-trace-devel-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-rt-trace-kvm-3.10.0-1160.21.1.rt56.1158.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-debug / kernel-rt-debug-devel / etc');
}