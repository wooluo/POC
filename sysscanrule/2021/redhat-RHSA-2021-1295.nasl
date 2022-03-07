##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1295. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148892);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id("CVE-2021-3347", "CVE-2021-27364", "CVE-2021-27365");
  script_xref(name:"RHSA", value:"2021:1295");

  script_name(english:"RHEL 8 : kpatch-patch (RHSA-2021:1295)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1295 advisory.

  - kernel: out-of-bounds read in libiscsi module (CVE-2021-27364)

  - kernel: heap buffer overflow in the iSCSI subsystem (CVE-2021-27365)

  - kernel: Use after free via PI futex state (CVE-2021-3347)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/250.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3347");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-27364");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-27365");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930080");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 200, 250, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_13_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_14_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_19_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_28_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_29_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_37_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_40_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_41_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_46_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_47_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-193_6_3");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.2')) audit(AUDIT_OS_NOT, 'Red Hat 8.2', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

repositories = {
    'rhel_aus_8_2_appstream': [
      'rhel-8-for-x86_64-appstream-aus-debug-rpms',
      'rhel-8-for-x86_64-appstream-aus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-aus-rpms',
      'rhel-8-for-x86_64-appstream-aus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-aus-source-rpms',
      'rhel-8-for-x86_64-appstream-aus-source-rpms__8_DOT_2'
    ],
    'rhel_aus_8_2_baseos': [
      'rhel-8-for-x86_64-baseos-aus-debug-rpms',
      'rhel-8-for-x86_64-baseos-aus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-aus-rpms',
      'rhel-8-for-x86_64-baseos-aus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-aus-source-rpms',
      'rhel-8-for-x86_64-baseos-aus-source-rpms__8_DOT_2'
    ],
    'rhel_e4s_8_2_appstream': [
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms',
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-e4s-rpms',
      'rhel-8-for-x86_64-appstream-e4s-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms__8_DOT_2'
    ],
    'rhel_e4s_8_2_baseos': [
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms',
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-e4s-rpms',
      'rhel-8-for-x86_64-baseos-e4s-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms__8_DOT_2'
    ],
    'rhel_e4s_8_2_highavailability': [
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms__8_DOT_2'
    ],
    'rhel_e4s_8_2_sap': [
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms__8_DOT_2'
    ],
    'rhel_e4s_8_2_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms__8_DOT_2'
    ],
    'rhel_eus_8_2_appstream': [
      'rhel-8-for-aarch64-appstream-eus-debug-rpms',
      'rhel-8-for-aarch64-appstream-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-aarch64-appstream-eus-rpms',
      'rhel-8-for-aarch64-appstream-eus-rpms__8_DOT_2',
      'rhel-8-for-aarch64-appstream-eus-source-rpms',
      'rhel-8-for-aarch64-appstream-eus-source-rpms__8_DOT_2',
      'rhel-8-for-s390x-appstream-eus-debug-rpms',
      'rhel-8-for-s390x-appstream-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-s390x-appstream-eus-rpms',
      'rhel-8-for-s390x-appstream-eus-rpms__8_DOT_2',
      'rhel-8-for-s390x-appstream-eus-source-rpms',
      'rhel-8-for-s390x-appstream-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-aus-debug-rpms',
      'rhel-8-for-x86_64-appstream-aus-rpms',
      'rhel-8-for-x86_64-appstream-aus-source-rpms',
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms',
      'rhel-8-for-x86_64-appstream-e4s-rpms',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms',
      'rhel-8-for-x86_64-appstream-eus-debug-rpms',
      'rhel-8-for-x86_64-appstream-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-eus-rpms',
      'rhel-8-for-x86_64-appstream-eus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-eus-source-rpms',
      'rhel-8-for-x86_64-appstream-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-tus-debug-rpms',
      'rhel-8-for-x86_64-appstream-tus-rpms',
      'rhel-8-for-x86_64-appstream-tus-source-rpms'
    ],
    'rhel_eus_8_2_baseos': [
      'rhel-8-for-aarch64-baseos-eus-debug-rpms',
      'rhel-8-for-aarch64-baseos-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-aarch64-baseos-eus-rpms',
      'rhel-8-for-aarch64-baseos-eus-rpms__8_DOT_2',
      'rhel-8-for-aarch64-baseos-eus-source-rpms',
      'rhel-8-for-aarch64-baseos-eus-source-rpms__8_DOT_2',
      'rhel-8-for-s390x-baseos-eus-debug-rpms',
      'rhel-8-for-s390x-baseos-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-s390x-baseos-eus-rpms',
      'rhel-8-for-s390x-baseos-eus-rpms__8_DOT_2',
      'rhel-8-for-s390x-baseos-eus-source-rpms',
      'rhel-8-for-s390x-baseos-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-aus-debug-rpms',
      'rhel-8-for-x86_64-baseos-aus-rpms',
      'rhel-8-for-x86_64-baseos-aus-source-rpms',
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms',
      'rhel-8-for-x86_64-baseos-e4s-rpms',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms',
      'rhel-8-for-x86_64-baseos-eus-debug-rpms',
      'rhel-8-for-x86_64-baseos-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-eus-rpms',
      'rhel-8-for-x86_64-baseos-eus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-eus-source-rpms',
      'rhel-8-for-x86_64-baseos-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-tus-debug-rpms',
      'rhel-8-for-x86_64-baseos-tus-rpms',
      'rhel-8-for-x86_64-baseos-tus-source-rpms'
    ],
    'rhel_eus_8_2_crb': [
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-s390x-eus-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms__8_DOT_2',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms__8_DOT_2'
    ],
    'rhel_eus_8_2_highavailability': [
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms',
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-aarch64-highavailability-eus-rpms',
      'rhel-8-for-aarch64-highavailability-eus-rpms__8_DOT_2',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms__8_DOT_2',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-s390x-highavailability-eus-rpms',
      'rhel-8-for-s390x-highavailability-eus-rpms__8_DOT_2',
      'rhel-8-for-s390x-highavailability-eus-source-rpms',
      'rhel-8-for-s390x-highavailability-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-eus-rpms',
      'rhel-8-for-x86_64-highavailability-eus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms'
    ],
    'rhel_eus_8_2_resilientstorage': [
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-s390x-resilientstorage-eus-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-rpms__8_DOT_2',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms__8_DOT_2'
    ],
    'rhel_eus_8_2_sap': [
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms__8_DOT_2',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms__8_DOT_2'
    ],
    'rhel_eus_8_2_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms__8_DOT_2'
    ],
    'rhel_eus_8_2_supplementary': [
      'rhel-8-for-aarch64-supplementary-eus-rpms',
      'rhel-8-for-aarch64-supplementary-eus-rpms__8_DOT_2',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms__8_DOT_2',
      'rhel-8-for-s390x-supplementary-eus-rpms',
      'rhel-8-for-s390x-supplementary-eus-rpms__8_DOT_2',
      'rhel-8-for-s390x-supplementary-eus-source-rpms',
      'rhel-8-for-s390x-supplementary-eus-source-rpms__8_DOT_2',
      'rhel-8-for-x86_64-supplementary-eus-rpms',
      'rhel-8-for-x86_64-supplementary-eus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms__8_DOT_2'
    ],
    'rhel_extras_nfv_8': [
      'rhel-8-for-x86_64-nfv-debug-rpms',
      'rhel-8-for-x86_64-nfv-rpms',
      'rhel-8-for-x86_64-nfv-source-rpms',
      'rhel-8-for-x86_64-nfv-tus-debug-rpms',
      'rhel-8-for-x86_64-nfv-tus-rpms',
      'rhel-8-for-x86_64-nfv-tus-source-rpms'
    ],
    'rhel_extras_rt_8': [
      'rhel-8-for-x86_64-nfv-debug-rpms',
      'rhel-8-for-x86_64-nfv-rpms',
      'rhel-8-for-x86_64-nfv-source-rpms',
      'rhel-8-for-x86_64-rt-debug-rpms',
      'rhel-8-for-x86_64-rt-rpms',
      'rhel-8-for-x86_64-rt-source-rpms',
      'rhel-8-for-x86_64-rt-tus-debug-rpms',
      'rhel-8-for-x86_64-rt-tus-rpms',
      'rhel-8-for-x86_64-rt-tus-source-rpms'
    ],
    'rhel_tus_8_2_appstream': [
      'rhel-8-for-x86_64-appstream-tus-debug-rpms',
      'rhel-8-for-x86_64-appstream-tus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-tus-rpms',
      'rhel-8-for-x86_64-appstream-tus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-appstream-tus-source-rpms',
      'rhel-8-for-x86_64-appstream-tus-source-rpms__8_DOT_2'
    ],
    'rhel_tus_8_2_baseos': [
      'rhel-8-for-x86_64-baseos-tus-debug-rpms',
      'rhel-8-for-x86_64-baseos-tus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-tus-rpms',
      'rhel-8-for-x86_64-baseos-tus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-baseos-tus-source-rpms',
      'rhel-8-for-x86_64-baseos-tus-source-rpms__8_DOT_2'
    ],
    'rhel_tus_8_2_highavailability': [
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms__8_DOT_2',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms__8_DOT_2'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || empty_or_null(repo_sets)) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

kernel_live_checks = {
    '4.18.0-193.el8.x86_64': {'reference':'kpatch-patch-4_18_0-193-1-13.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.13.2.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_13_2-1-8.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.14.3.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_14_3-1-8.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.19.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_19_1-1-8.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.1.2.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_1_2-1-11.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.28.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_28_1-1-6.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.29.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_29_1-1-6.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.37.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_37_1-1-6.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.40.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_40_1-1-6.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.41.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_41_1-1-6.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.46.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_46_1-1-3.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.47.1.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_47_1-1-3.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']},
    '4.18.0-193.6.3.el8_2.x86_64': {'reference':'kpatch-patch-4_18_0-193_6_3-1-10.el8_2', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpatch-patch-4_18_0-193 / kpatch-patch-4_18_0-193_13_2 / etc');
}
