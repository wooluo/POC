
##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:2714. The text
# itself is copyright (C) Red Hat, Inc.
##



include('compat.inc');

if (description)
{
  script_id(151846);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/30");

  script_cve_id("CVE-2021-32399", "CVE-2021-33909");
  script_xref(name:"RHSA", value:"2021:2714");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"RHEL 8 : kernel (RHSA-2021:2714)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:2714 advisory.

  - kernel: race condition for removal of the HCI controller (CVE-2021-32399)

  - kernel: size_t-to-int conversion vulnerability in the filesystem layer (CVE-2021-33909)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/362.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-32399");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1970273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1970807");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33909");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(362, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-stablelists");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  cve_list = make_list('CVE-2021-32399', 'CVE-2021-33909');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:2714');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'bpftool-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'bpftool-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'bpftool-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-abi-stablelists-4.18.0-305.10.2.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-core-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-core-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-core-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-cross-headers-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-cross-headers-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-cross-headers-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-core-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-core-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-core-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-extra-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-extra-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-debug-modules-extra-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-extra-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-extra-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-modules-extra-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-tools-libs-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-core-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-devel-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-modules-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'perf-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'perf-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'perf-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'python3-perf-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'python3-perf-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']},
    {'reference':'python3-perf-4.18.0-305.10.2.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['enterprise_linux_8_appstream', 'enterprise_linux_8_baseos', 'enterprise_linux_8_crb', 'enterprise_linux_8_highavailability', 'enterprise_linux_8_nfv', 'enterprise_linux_8_realtime', 'enterprise_linux_8_resilientstorage', 'enterprise_linux_8_sap', 'enterprise_linux_8_sap_hana', 'enterprise_linux_8_supplementary', 'rhel_aus_8_4_appstream', 'rhel_aus_8_4_baseos', 'rhel_e4s_8_4_appstream', 'rhel_e4s_8_4_baseos', 'rhel_e4s_8_4_highavailability', 'rhel_e4s_8_4_sap', 'rhel_e4s_8_4_sap_hana', 'rhel_eus_8_4_appstream', 'rhel_eus_8_4_baseos', 'rhel_eus_8_4_crb', 'rhel_eus_8_4_highavailability', 'rhel_eus_8_4_resilientstorage', 'rhel_eus_8_4_sap', 'rhel_eus_8_4_sap_hana', 'rhel_eus_8_4_supplementary', 'rhel_extras_nfv_8', 'rhel_extras_rt_8', 'rhel_tus_8_4_appstream', 'rhel_tus_8_4_baseos', 'rhel_tus_8_4_highavailability']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
