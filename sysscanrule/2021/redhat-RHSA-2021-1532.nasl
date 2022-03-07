
##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1532. The text
# itself is copyright (C) Red Hat, Inc.
##


include('compat.inc');

if (description)
{
  script_id(149441);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id("CVE-2020-28374", "CVE-2021-27364", "CVE-2021-27365");
  script_xref(name:"RHSA", value:"2021:1532");

  script_name(english:"RHEL 7 : kpatch-patch (RHSA-2021:1532)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1532 advisory.

  - kernel: SCSI target (LIO) write to any block on ILO backstore (CVE-2020-28374)

  - kernel: out-of-bounds read in libiscsi module (CVE-2021-27364)

  - kernel: heap buffer overflow in the iSCSI subsystem (CVE-2021-27365)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/250.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-27364");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-27365");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1899804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930080");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 122, 125, 200, 250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:7.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_26_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_30_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_31_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_31_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_33_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_36_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_37_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_40_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_43_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_45_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_46_1");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.7')) audit(AUDIT_OS_NOT, 'Red Hat 7.7', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

repositories = {
    'rhel_aus_7_7_server': [
      'rhel-7-server-aus-debug-rpms',
      'rhel-7-server-aus-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-aus-optional-debug-rpms',
      'rhel-7-server-aus-optional-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-aus-optional-rpms',
      'rhel-7-server-aus-optional-rpms__7_DOT_7__x86_64',
      'rhel-7-server-aus-optional-source-rpms',
      'rhel-7-server-aus-optional-source-rpms__7_DOT_7__x86_64',
      'rhel-7-server-aus-rpms',
      'rhel-7-server-aus-rpms__7_DOT_7__x86_64',
      'rhel-7-server-aus-source-rpms',
      'rhel-7-server-aus-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_e4s_7_7_server': [
      'rhel-7-server-aus-debug-rpms',
      'rhel-7-server-aus-rpms',
      'rhel-7-server-aus-source-rpms',
      'rhel-7-server-e4s-debug-rpms',
      'rhel-7-server-e4s-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-e4s-rpms',
      'rhel-7-server-e4s-rpms__7_DOT_7__x86_64',
      'rhel-7-server-e4s-source-rpms',
      'rhel-7-server-e4s-source-rpms__7_DOT_7__x86_64',
      'rhel-7-server-tus-debug-rpms',
      'rhel-7-server-tus-rpms',
      'rhel-7-server-tus-source-rpms'
    ],
    'rhel_eus_7_7_computenode': [
      'rhel-7-hpc-node-eus-debug-rpms',
      'rhel-7-hpc-node-eus-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-hpc-node-eus-optional-debug-rpms',
      'rhel-7-hpc-node-eus-optional-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-hpc-node-eus-optional-rpms',
      'rhel-7-hpc-node-eus-optional-rpms__7_DOT_7__x86_64',
      'rhel-7-hpc-node-eus-optional-source-rpms',
      'rhel-7-hpc-node-eus-optional-source-rpms__7_DOT_7__x86_64',
      'rhel-7-hpc-node-eus-rpms',
      'rhel-7-hpc-node-eus-rpms__7_DOT_7__x86_64',
      'rhel-7-hpc-node-eus-source-rpms',
      'rhel-7-hpc-node-eus-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_eus_7_7_server': [
      'rhel-7-server-aus-debug-rpms',
      'rhel-7-server-aus-optional-debug-rpms',
      'rhel-7-server-aus-optional-rpms',
      'rhel-7-server-aus-optional-source-rpms',
      'rhel-7-server-aus-rpms',
      'rhel-7-server-aus-source-rpms',
      'rhel-7-server-e4s-debug-rpms',
      'rhel-7-server-e4s-optional-debug-rpms',
      'rhel-7-server-e4s-optional-rpms',
      'rhel-7-server-e4s-optional-source-rpms',
      'rhel-7-server-e4s-rpms',
      'rhel-7-server-e4s-source-rpms',
      'rhel-7-server-eus-debug-rpms',
      'rhel-7-server-eus-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-eus-optional-debug-rpms',
      'rhel-7-server-eus-optional-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-eus-optional-rpms',
      'rhel-7-server-eus-optional-rpms__7_DOT_7__x86_64',
      'rhel-7-server-eus-optional-source-rpms',
      'rhel-7-server-eus-optional-source-rpms__7_DOT_7__x86_64',
      'rhel-7-server-eus-rpms',
      'rhel-7-server-eus-rpms__7_DOT_7__x86_64',
      'rhel-7-server-eus-source-rpms',
      'rhel-7-server-eus-source-rpms__7_DOT_7__x86_64',
      'rhel-7-server-tus-debug-rpms',
      'rhel-7-server-tus-optional-debug-rpms',
      'rhel-7-server-tus-optional-rpms',
      'rhel-7-server-tus-optional-source-rpms',
      'rhel-7-server-tus-rpms',
      'rhel-7-server-tus-source-rpms',
      'rhel-ha-for-rhel-7-server-e4s-debug-rpms',
      'rhel-ha-for-rhel-7-server-e4s-rpms',
      'rhel-ha-for-rhel-7-server-e4s-source-rpms',
      'rhel-ha-for-rhel-7-server-eus-debug-rpms',
      'rhel-ha-for-rhel-7-server-eus-debug-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-eus-rpms',
      'rhel-ha-for-rhel-7-server-eus-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-eus-source-rpms',
      'rhel-ha-for-rhel-7-server-eus-source-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-tus-debug-rpms',
      'rhel-ha-for-rhel-7-server-tus-rpms',
      'rhel-ha-for-rhel-7-server-tus-source-rpms',
      'rhel-rs-for-rhel-7-server-eus-debug-rpms',
      'rhel-rs-for-rhel-7-server-eus-debug-rpms__7_DOT_7__x86_64',
      'rhel-rs-for-rhel-7-server-eus-rpms',
      'rhel-rs-for-rhel-7-server-eus-rpms__7_DOT_7__x86_64',
      'rhel-rs-for-rhel-7-server-eus-source-rpms',
      'rhel-rs-for-rhel-7-server-eus-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_extras_sap_e4s_7_7': [
      'rhel-sap-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-for-rhel-7-server-e4s-debug-rpms__7_DOT_7__x86_64',
      'rhel-sap-for-rhel-7-server-e4s-rpms',
      'rhel-sap-for-rhel-7-server-e4s-rpms__7_DOT_7__x86_64',
      'rhel-sap-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-for-rhel-7-server-e4s-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_extras_sap_eus_7_7': [
      'rhel-sap-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-for-rhel-7-server-e4s-rpms',
      'rhel-sap-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-for-rhel-7-server-eus-debug-rpms',
      'rhel-sap-for-rhel-7-server-eus-debug-rpms__7_DOT_7__x86_64',
      'rhel-sap-for-rhel-7-server-eus-rpms',
      'rhel-sap-for-rhel-7-server-eus-rpms__7_DOT_7__x86_64',
      'rhel-sap-for-rhel-7-server-eus-source-rpms',
      'rhel-sap-for-rhel-7-server-eus-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_extras_sap_hana_e4s_7_7': [
      'rhel-sap-hana-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-debug-rpms__7_DOT_7__x86_64',
      'rhel-sap-hana-for-rhel-7-server-e4s-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-rpms__7_DOT_7__x86_64',
      'rhel-sap-hana-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_extras_sap_hana_eus_7_7': [
      'rhel-sap-hana-for-rhel-7-server-e4s-debug-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-rpms',
      'rhel-sap-hana-for-rhel-7-server-e4s-source-rpms',
      'rhel-sap-hana-for-rhel-7-server-eus-debug-rpms',
      'rhel-sap-hana-for-rhel-7-server-eus-debug-rpms__7_DOT_7__x86_64',
      'rhel-sap-hana-for-rhel-7-server-eus-rpms',
      'rhel-sap-hana-for-rhel-7-server-eus-rpms__7_DOT_7__x86_64',
      'rhel-sap-hana-for-rhel-7-server-eus-source-rpms',
      'rhel-sap-hana-for-rhel-7-server-eus-source-rpms__7_DOT_7__x86_64'
    ],
    'rhel_tus_7_7_server': [
      'rhel-7-server-tus-debug-rpms',
      'rhel-7-server-tus-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-tus-optional-debug-rpms',
      'rhel-7-server-tus-optional-debug-rpms__7_DOT_7__x86_64',
      'rhel-7-server-tus-optional-rpms',
      'rhel-7-server-tus-optional-rpms__7_DOT_7__x86_64',
      'rhel-7-server-tus-optional-source-rpms',
      'rhel-7-server-tus-optional-source-rpms__7_DOT_7__x86_64',
      'rhel-7-server-tus-rpms',
      'rhel-7-server-tus-rpms__7_DOT_7__x86_64',
      'rhel-7-server-tus-source-rpms',
      'rhel-7-server-tus-source-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-tus-debug-rpms',
      'rhel-ha-for-rhel-7-server-tus-debug-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-tus-rpms',
      'rhel-ha-for-rhel-7-server-tus-rpms__7_DOT_7__x86_64',
      'rhel-ha-for-rhel-7-server-tus-source-rpms',
      'rhel-ha-for-rhel-7-server-tus-source-rpms__7_DOT_7__x86_64'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || empty_or_null(repo_sets)) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

kernel_live_checks = {
    '3.10.0-1062.26.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_26_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.30.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_30_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.31.2.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_31_2-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.31.3.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_31_3-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.33.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_33_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.36.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_36_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.37.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_37_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.40.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_40_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.43.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_43_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.45.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_45_1-1-3.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']},
    '3.10.0-1062.46.1.el7.x86_64': {'reference':'kpatch-patch-3_10_0-1062_46_1-1-2.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_7_7_server', 'rhel_e4s_7_7_server', 'rhel_eus_7_7_computenode', 'rhel_eus_7_7_server', 'rhel_extras_sap_e4s_7_7', 'rhel_extras_sap_eus_7_7', 'rhel_extras_sap_hana_e4s_7_7', 'rhel_extras_sap_hana_eus_7_7', 'rhel_tus_7_7_server']}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpatch-patch-3_10_0-1062_26_1 / kpatch-patch-3_10_0-1062_30_1 / etc');
}
