##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5437. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144404);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id(
    "CVE-2019-18282",
    "CVE-2020-10769",
    "CVE-2020-14314",
    "CVE-2020-14385",
    "CVE-2020-24394",
    "CVE-2020-25212",
    "CVE-2020-25643"
  );
  script_xref(name:"RHSA", value:"2020:5437");

  script_name(english:"RHEL 7 : kernel (RHSA-2020:5437)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:5437 advisory.

  - kernel: The flow_dissector feature allows device tracking (CVE-2019-18282)

  - kernel: Buffer over-read in crypto_authenc_extractkeys() when a payload longer than 4 bytes is not
    aligned. (CVE-2020-10769)

  - kernel: buffer uses out of index in ext3/4 filesystem (CVE-2020-14314)

  - kernel: metadata validator in XFS may cause an inode with a valid, user-creatable extended attribute to be
    flagged as corrupt (CVE-2020-14385)

  - kernel: umask not applied on filesystem without ACL support (CVE-2020-24394)

  - kernel: TOCTOU mismatch in the NFS client code (CVE-2020-25212)

  - kernel: improper input validation in ppp_cp_parse_cr function leads to memory corruption and read overflow
    (CVE-2020-25643)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/131.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/367.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/732.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18282");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10769");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14314");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14385");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25212");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1708775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1853922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1869141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1874800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879981");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 125, 131, 200, 367, 732);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'rhel-7-for-system-z-a-debug-rpms',
      'rhel-7-for-system-z-a-optional-debug-rpms',
      'rhel-7-for-system-z-a-optional-rpms',
      'rhel-7-for-system-z-a-optional-source-rpms',
      'rhel-7-for-system-z-a-rpms',
      'rhel-7-for-system-z-a-source-rpms',
      'rhel-7-for-system-z-debug-rpms',
      'rhel-7-for-system-z-fastrack-debug-rpms',
      'rhel-7-for-system-z-fastrack-rpms',
      'rhel-7-for-system-z-fastrack-source-rpms',
      'rhel-7-for-system-z-optional-debug-rpms',
      'rhel-7-for-system-z-optional-fastrack-debug-rpms',
      'rhel-7-for-system-z-optional-fastrack-rpms',
      'rhel-7-for-system-z-optional-fastrack-source-rpms',
      'rhel-7-for-system-z-optional-rpms',
      'rhel-7-for-system-z-optional-source-rpms',
      'rhel-7-for-system-z-rpms',
      'rhel-7-for-system-z-source-rpms',
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
      'rhel-ha-for-rhel-7-for-system-z-debug-rpms',
      'rhel-ha-for-rhel-7-for-system-z-rpms',
      'rhel-ha-for-rhel-7-for-system-z-source-rpms',
      'rhel-ha-for-rhel-7-server-debug-rpms',
      'rhel-ha-for-rhel-7-server-rpms',
      'rhel-ha-for-rhel-7-server-source-rpms',
      'rhel-rs-for-rhel-7-for-system-z-debug-rpms',
      'rhel-rs-for-rhel-7-for-system-z-rpms',
      'rhel-rs-for-rhel-7-for-system-z-source-rpms',
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
      'rhel-7-for-system-z-eus-supplementary-rpms',
      'rhel-7-for-system-z-eus-supplementary-source-rpms',
      'rhel-7-for-system-z-supplementary-debug-rpms',
      'rhel-7-for-system-z-supplementary-rpms',
      'rhel-7-for-system-z-supplementary-source-rpms',
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
      'rhel-sap-for-rhel-7-for-system-z-debug-rpms',
      'rhel-sap-for-rhel-7-for-system-z-eus-debug-rpms',
      'rhel-sap-for-rhel-7-for-system-z-eus-rpms',
      'rhel-sap-for-rhel-7-for-system-z-eus-source-rpms',
      'rhel-sap-for-rhel-7-for-system-z-rpms',
      'rhel-sap-for-rhel-7-for-system-z-source-rpms',
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
  cve_list = make_list('CVE-2019-18282', 'CVE-2020-10769', 'CVE-2020-14314', 'CVE-2020-14385', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25643');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:5437');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'bpftool-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'bpftool-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-abi-whitelists-3.10.0-1160.11.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-debug-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-debug-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-debug-devel-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-debug-devel-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-devel-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-devel-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-kdump-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-kdump-devel-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-tools-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-tools-libs-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'kernel-tools-libs-devel-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'perf-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'perf-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'python-perf-3.10.0-1160.11.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']},
    {'reference':'python-perf-3.10.0-1160.11.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_7_client', 'enterprise_linux_7_computenode', 'enterprise_linux_7_server', 'enterprise_linux_7_workstation', 'rhel_extras_7', 'rhel_extras_oracle_java_7', 'rhel_extras_rt_7', 'rhel_extras_sap_7', 'rhel_extras_sap_hana_7']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-debug / etc');
}
