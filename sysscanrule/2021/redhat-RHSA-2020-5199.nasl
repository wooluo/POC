##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5199. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143236);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id("CVE-2020-14385", "CVE-2020-14386");
  script_xref(name:"RHSA", value:"2020:5199");

  script_name(english:"RHEL 8 : kernel (RHSA-2020:5199)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:5199 advisory.

  - kernel: metadata validator in XFS may cause an inode with a valid, user-creatable extended attribute to be
    flagged as corrupt (CVE-2020-14385)

  - kernel: memory corruption in net/packet/af_packet.c leads to elevation of privilege (CVE-2020-14386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/131.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/250.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14385");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1874800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1875699");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(131, 250, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

repositories = {
    'rhel_e4s_8_0_appstream': [
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms',
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms__8_DOT_0',
      'rhel-8-for-x86_64-appstream-e4s-rpms',
      'rhel-8-for-x86_64-appstream-e4s-rpms__8_DOT_0',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms__8_DOT_0'
    ],
    'rhel_e4s_8_0_baseos': [
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms',
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms__8_DOT_0',
      'rhel-8-for-x86_64-baseos-e4s-rpms',
      'rhel-8-for-x86_64-baseos-e4s-rpms__8_DOT_0',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms__8_DOT_0'
    ],
    'rhel_e4s_8_0_highavailability': [
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms__8_DOT_0',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms__8_DOT_0',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms__8_DOT_0'
    ],
    'rhel_e4s_8_0_sap': [
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms__8_DOT_0',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms__8_DOT_0',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms__8_DOT_0'
    ],
    'rhel_e4s_8_0_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms__8_DOT_0',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms__8_DOT_0'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || empty_or_null(repo_sets)) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-14385', 'CVE-2020-14386');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:5199');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'bpftool-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'bpftool-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'bpftool-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-abi-whitelists-4.18.0-80.31.1.el8_0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-core-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-core-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-core-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-cross-headers-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-cross-headers-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-cross-headers-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-core-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-core-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-core-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-devel-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-devel-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-devel-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-modules-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-modules-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-modules-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-modules-extra-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-modules-extra-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-debug-modules-extra-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-devel-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-devel-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-devel-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-modules-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-modules-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-modules-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-modules-extra-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-modules-extra-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-modules-extra-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-tools-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-tools-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-tools-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-tools-libs-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-tools-libs-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-zfcpdump-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-zfcpdump-core-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-zfcpdump-devel-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-zfcpdump-modules-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'perf-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'perf-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'perf-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'python3-perf-4.18.0-80.31.1.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'python3-perf-4.18.0-80.31.1.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']},
    {'reference':'python3-perf-4.18.0-80.31.1.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_e4s_8_0_appstream', 'rhel_e4s_8_0_baseos', 'rhel_e4s_8_0_highavailability', 'rhel_e4s_8_0_sap', 'rhel_e4s_8_0_sap_hana']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-core / etc');
}
