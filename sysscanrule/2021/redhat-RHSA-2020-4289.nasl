##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4289. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141603);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id(
    "CVE-2020-12351",
    "CVE-2020-12352",
    "CVE-2020-14331",
    "CVE-2020-14385",
    "CVE-2020-14386"
  );
  script_xref(name:"RHSA", value:"2020:4289");

  script_name(english:"RHEL 8 : kernel-rt (RHSA-2020:4289)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4289 advisory.

  - kernel: net: bluetooth: type confusion while processing AMP packets (CVE-2020-12351)

  - kernel: net: bluetooth: information leak when processing certain AMP packets (CVE-2020-12352)

  - kernel: kernel: buffer over write in vgacon_scroll (CVE-2020-14331)

  - kernel: metadata validator in XFS may cause an inode with a valid, user-creatable extended attribute to be
    flagged as corrupt (CVE-2020-14385)

  - kernel: memory corruption in net/packet/af_packet.c leads to elevation of privilege (CVE-2020-14386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/131.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/201.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/250.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/284.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/843.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12352");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14331");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14385");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1858679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1874800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1875699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1886521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1886529");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14386");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(131, 201, 250, 284, 787, 843);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
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
    'enterprise_linux_8_appstream': [
      'rhel-8-for-aarch64-appstream-debug-rpms',
      'rhel-8-for-aarch64-appstream-rpms',
      'rhel-8-for-aarch64-appstream-source-rpms',
      'rhel-8-for-s390x-appstream-debug-rpms',
      'rhel-8-for-s390x-appstream-rpms',
      'rhel-8-for-s390x-appstream-source-rpms',
      'rhel-8-for-x86_64-appstream-debug-rpms',
      'rhel-8-for-x86_64-appstream-rpms',
      'rhel-8-for-x86_64-appstream-source-rpms'
    ],
    'enterprise_linux_8_baseos': [
      'rhel-8-for-aarch64-baseos-debug-rpms',
      'rhel-8-for-aarch64-baseos-rpms',
      'rhel-8-for-aarch64-baseos-source-rpms',
      'rhel-8-for-s390x-baseos-debug-rpms',
      'rhel-8-for-s390x-baseos-rpms',
      'rhel-8-for-s390x-baseos-source-rpms',
      'rhel-8-for-x86_64-baseos-debug-rpms',
      'rhel-8-for-x86_64-baseos-rpms',
      'rhel-8-for-x86_64-baseos-source-rpms'
    ],
    'enterprise_linux_8_crb': [
      'codeready-builder-for-rhel-8-aarch64-debug-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms',
      'codeready-builder-for-rhel-8-aarch64-rpms',
      'codeready-builder-for-rhel-8-aarch64-source-rpms',
      'codeready-builder-for-rhel-8-s390x-debug-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms',
      'codeready-builder-for-rhel-8-s390x-rpms',
      'codeready-builder-for-rhel-8-s390x-source-rpms',
      'codeready-builder-for-rhel-8-x86_64-debug-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms',
      'codeready-builder-for-rhel-8-x86_64-rpms',
      'codeready-builder-for-rhel-8-x86_64-source-rpms'
    ],
    'enterprise_linux_8_highavailability': [
      'rhel-8-for-aarch64-highavailability-debug-rpms',
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms',
      'rhel-8-for-aarch64-highavailability-eus-rpms',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms',
      'rhel-8-for-aarch64-highavailability-rpms',
      'rhel-8-for-aarch64-highavailability-source-rpms',
      'rhel-8-for-s390x-highavailability-debug-rpms',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms',
      'rhel-8-for-s390x-highavailability-eus-rpms',
      'rhel-8-for-s390x-highavailability-eus-source-rpms',
      'rhel-8-for-s390x-highavailability-rpms',
      'rhel-8-for-s390x-highavailability-source-rpms',
      'rhel-8-for-x86_64-highavailability-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-eus-rpms',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms',
      'rhel-8-for-x86_64-highavailability-rpms',
      'rhel-8-for-x86_64-highavailability-source-rpms',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms'
    ],
    'enterprise_linux_8_nfv': [
      'rhel-8-for-x86_64-nfv-debug-rpms',
      'rhel-8-for-x86_64-nfv-rpms',
      'rhel-8-for-x86_64-nfv-source-rpms',
      'rhel-8-for-x86_64-nfv-tus-debug-rpms',
      'rhel-8-for-x86_64-nfv-tus-rpms',
      'rhel-8-for-x86_64-nfv-tus-source-rpms'
    ],
    'enterprise_linux_8_realtime': [
      'rhel-8-for-x86_64-rt-debug-rpms',
      'rhel-8-for-x86_64-rt-rpms',
      'rhel-8-for-x86_64-rt-source-rpms',
      'rhel-8-for-x86_64-rt-tus-debug-rpms',
      'rhel-8-for-x86_64-rt-tus-rpms',
      'rhel-8-for-x86_64-rt-tus-source-rpms'
    ],
    'enterprise_linux_8_resilientstorage': [
      'rhel-8-for-s390x-resilientstorage-debug-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms',
      'rhel-8-for-s390x-resilientstorage-rpms',
      'rhel-8-for-s390x-resilientstorage-source-rpms',
      'rhel-8-for-x86_64-resilientstorage-debug-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms',
      'rhel-8-for-x86_64-resilientstorage-rpms',
      'rhel-8-for-x86_64-resilientstorage-source-rpms'
    ],
    'enterprise_linux_8_sap': [
      'rhel-8-for-s390x-sap-netweaver-debug-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms',
      'rhel-8-for-s390x-sap-netweaver-rpms',
      'rhel-8-for-s390x-sap-netweaver-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-rpms',
      'rhel-8-for-x86_64-sap-netweaver-source-rpms'
    ],
    'enterprise_linux_8_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-rpms',
      'rhel-8-for-x86_64-sap-solutions-source-rpms'
    ],
    'enterprise_linux_8_supplementary': [
      'rhel-8-for-aarch64-supplementary-eus-rpms',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms',
      'rhel-8-for-aarch64-supplementary-rpms',
      'rhel-8-for-aarch64-supplementary-source-rpms',
      'rhel-8-for-s390x-supplementary-eus-rpms',
      'rhel-8-for-s390x-supplementary-eus-source-rpms',
      'rhel-8-for-s390x-supplementary-rpms',
      'rhel-8-for-s390x-supplementary-source-rpms',
      'rhel-8-for-x86_64-supplementary-eus-rpms',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms',
      'rhel-8-for-x86_64-supplementary-rpms',
      'rhel-8-for-x86_64-supplementary-source-rpms'
    ],
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
    'rhel_aus_8_4_appstream': [
      'rhel-8-for-x86_64-appstream-aus-debug-rpms',
      'rhel-8-for-x86_64-appstream-aus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-aus-rpms',
      'rhel-8-for-x86_64-appstream-aus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-aus-source-rpms',
      'rhel-8-for-x86_64-appstream-aus-source-rpms__8_DOT_4'
    ],
    'rhel_aus_8_4_baseos': [
      'rhel-8-for-x86_64-baseos-aus-debug-rpms',
      'rhel-8-for-x86_64-baseos-aus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-aus-rpms',
      'rhel-8-for-x86_64-baseos-aus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-aus-source-rpms',
      'rhel-8-for-x86_64-baseos-aus-source-rpms__8_DOT_4'
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
    'rhel_e4s_8_4_appstream': [
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms',
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-e4s-rpms',
      'rhel-8-for-x86_64-appstream-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_baseos': [
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms',
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-e4s-rpms',
      'rhel-8-for-x86_64-baseos-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_highavailability': [
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_sap': [
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms__8_DOT_4'
    ],
    'rhel_e4s_8_4_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms__8_DOT_4'
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
    'rhel_eus_8_4_appstream': [
      'rhel-8-for-aarch64-appstream-eus-debug-rpms',
      'rhel-8-for-aarch64-appstream-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-aarch64-appstream-eus-rpms',
      'rhel-8-for-aarch64-appstream-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-appstream-eus-source-rpms',
      'rhel-8-for-aarch64-appstream-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-appstream-eus-debug-rpms',
      'rhel-8-for-s390x-appstream-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-appstream-eus-rpms',
      'rhel-8-for-s390x-appstream-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-appstream-eus-source-rpms',
      'rhel-8-for-s390x-appstream-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-aus-debug-rpms',
      'rhel-8-for-x86_64-appstream-aus-rpms',
      'rhel-8-for-x86_64-appstream-aus-source-rpms',
      'rhel-8-for-x86_64-appstream-e4s-debug-rpms',
      'rhel-8-for-x86_64-appstream-e4s-rpms',
      'rhel-8-for-x86_64-appstream-e4s-source-rpms',
      'rhel-8-for-x86_64-appstream-eus-debug-rpms',
      'rhel-8-for-x86_64-appstream-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-eus-rpms',
      'rhel-8-for-x86_64-appstream-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-eus-source-rpms',
      'rhel-8-for-x86_64-appstream-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-tus-debug-rpms',
      'rhel-8-for-x86_64-appstream-tus-rpms',
      'rhel-8-for-x86_64-appstream-tus-source-rpms'
    ],
    'rhel_eus_8_4_baseos': [
      'rhel-8-for-aarch64-baseos-eus-debug-rpms',
      'rhel-8-for-aarch64-baseos-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-aarch64-baseos-eus-rpms',
      'rhel-8-for-aarch64-baseos-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-baseos-eus-source-rpms',
      'rhel-8-for-aarch64-baseos-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-baseos-eus-debug-rpms',
      'rhel-8-for-s390x-baseos-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-baseos-eus-rpms',
      'rhel-8-for-s390x-baseos-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-baseos-eus-source-rpms',
      'rhel-8-for-s390x-baseos-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-aus-debug-rpms',
      'rhel-8-for-x86_64-baseos-aus-rpms',
      'rhel-8-for-x86_64-baseos-aus-source-rpms',
      'rhel-8-for-x86_64-baseos-e4s-debug-rpms',
      'rhel-8-for-x86_64-baseos-e4s-rpms',
      'rhel-8-for-x86_64-baseos-e4s-source-rpms',
      'rhel-8-for-x86_64-baseos-eus-debug-rpms',
      'rhel-8-for-x86_64-baseos-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-eus-rpms',
      'rhel-8-for-x86_64-baseos-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-eus-source-rpms',
      'rhel-8-for-x86_64-baseos-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-tus-debug-rpms',
      'rhel-8-for-x86_64-baseos-tus-rpms',
      'rhel-8-for-x86_64-baseos-tus-source-rpms'
    ],
    'rhel_eus_8_4_crb': [
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-debug-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms',
      'codeready-builder-for-rhel-8-aarch64-eus-source-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-debug-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-s390x-eus-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms',
      'codeready-builder-for-rhel-8-s390x-eus-source-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-debug-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-rpms__8_DOT_4',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms',
      'codeready-builder-for-rhel-8-x86_64-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_highavailability': [
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms',
      'rhel-8-for-aarch64-highavailability-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-aarch64-highavailability-eus-rpms',
      'rhel-8-for-aarch64-highavailability-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms',
      'rhel-8-for-aarch64-highavailability-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms',
      'rhel-8-for-s390x-highavailability-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-highavailability-eus-rpms',
      'rhel-8-for-s390x-highavailability-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-highavailability-eus-source-rpms',
      'rhel-8-for-s390x-highavailability-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-e4s-debug-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-rpms',
      'rhel-8-for-x86_64-highavailability-e4s-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-eus-rpms',
      'rhel-8-for-x86_64-highavailability-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms',
      'rhel-8-for-x86_64-highavailability-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms'
    ],
    'rhel_eus_8_4_resilientstorage': [
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-resilientstorage-eus-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms',
      'rhel-8-for-s390x-resilientstorage-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms',
      'rhel-8-for-x86_64-resilientstorage-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_sap': [
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms',
      'rhel-8-for-s390x-sap-netweaver-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-rpms',
      'rhel-8-for-x86_64-sap-netweaver-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms',
      'rhel-8-for-x86_64-sap-netweaver-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_sap_hana': [
      'rhel-8-for-x86_64-sap-solutions-e4s-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-rpms',
      'rhel-8-for-x86_64-sap-solutions-e4s-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms',
      'rhel-8-for-x86_64-sap-solutions-eus-source-rpms__8_DOT_4'
    ],
    'rhel_eus_8_4_supplementary': [
      'rhel-8-for-aarch64-supplementary-eus-rpms',
      'rhel-8-for-aarch64-supplementary-eus-rpms__8_DOT_4',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms',
      'rhel-8-for-aarch64-supplementary-eus-source-rpms__8_DOT_4',
      'rhel-8-for-s390x-supplementary-eus-rpms',
      'rhel-8-for-s390x-supplementary-eus-rpms__8_DOT_4',
      'rhel-8-for-s390x-supplementary-eus-source-rpms',
      'rhel-8-for-s390x-supplementary-eus-source-rpms__8_DOT_4',
      'rhel-8-for-x86_64-supplementary-eus-rpms',
      'rhel-8-for-x86_64-supplementary-eus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms',
      'rhel-8-for-x86_64-supplementary-eus-source-rpms__8_DOT_4'
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
    ],
    'rhel_tus_8_4_appstream': [
      'rhel-8-for-x86_64-appstream-tus-debug-rpms',
      'rhel-8-for-x86_64-appstream-tus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-tus-rpms',
      'rhel-8-for-x86_64-appstream-tus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-appstream-tus-source-rpms',
      'rhel-8-for-x86_64-appstream-tus-source-rpms__8_DOT_4'
    ],
    'rhel_tus_8_4_baseos': [
      'rhel-8-for-x86_64-baseos-tus-debug-rpms',
      'rhel-8-for-x86_64-baseos-tus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-tus-rpms',
      'rhel-8-for-x86_64-baseos-tus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-baseos-tus-source-rpms',
      'rhel-8-for-x86_64-baseos-tus-source-rpms__8_DOT_4'
    ],
    'rhel_tus_8_4_highavailability': [
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms',
      'rhel-8-for-x86_64-highavailability-tus-debug-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-tus-rpms',
      'rhel-8-for-x86_64-highavailability-tus-rpms__8_DOT_4',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms',
      'rhel-8-for-x86_64-highavailability-tus-source-rpms__8_DOT_4'
    ]
};

repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
enterprise_linux_flag = rhel_repo_sets_has_enterprise_linux(repo_sets:repo_sets);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE) audit(AUDIT_PACKAGE_LIST_MISSING, RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-12351', 'CVE-2020-12352', 'CVE-2020-14331', 'CVE-2020-14385', 'CVE-2020-14386');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:4289');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'kernel-rt-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-core-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-core-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-devel-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-kvm-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-modules-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-devel-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-kvm-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-modules-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-rt-modules-extra-4.18.0-193.28.1.rt13.77.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_2_appstream', 'rhel_aus_8_2_baseos', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_2_appstream', 'rhel_e4s_8_2_baseos', 'rhel_e4s_8_2_highavailability', 'rhel_e4s_8_2_sap', 'rhel_e4s_8_2_sap_hana', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_2_appstream', 'rhel_eus_8_2_baseos', 'rhel_eus_8_2_crb', 'rhel_eus_8_2_highavailability', 'rhel_eus_8_2_resilientstorage', 'rhel_eus_8_2_sap', 'rhel_eus_8_2_sap_hana', 'rhel_eus_8_2_supplementary', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_2_appstream', 'rhel_tus_8_2_baseos', 'rhel_tus_8_2_highavailability', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']}
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
  if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
