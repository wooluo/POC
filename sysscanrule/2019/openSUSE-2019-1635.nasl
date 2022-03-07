#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1635.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126326);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/28 11:31:56");

  script_cve_id("CVE-2018-16837", "CVE-2018-16859", "CVE-2018-16876", "CVE-2019-3828");

  script_name(english:"openSUSE Security Update : ansible (openSUSE-2019-1635)");
  script_summary(english:"Check for the openSUSE-2019-1635 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ansible fixes the following issues :

Ansible was updated to version 2.8.1 :

Full changelog is at /usr/share/doc/packages/ansible/changelogs/

  - Bugfixes

  - ACI - DO not encode query_string

  - ACI modules - Fix non-signature authentication

  - Add missing directory provided via ``--playbook-dir`` to
    adjacent collection loading

  - Fix 'Interface not found' errors when using
    eos_l2_interface with non-existent interfaces configured

  - Fix cannot get credential when `source_auth` set to
    `credential_file`.

  - Fix netconf_config backup string issue

  - Fix privilege escalation support for the docker
    connection plugin when credentials need to be supplied
    (e.g. sudo with password).

  - Fix vyos cli prompt inspection

  - Fixed loading namespaced documentation fragments from
    collections.

  - Fixing bug came up after running cnos_vrf module against
    coverity.

  - Properly handle data importer failures on PVC creation,
    instead of timing out.

  - To fix the ios static route TC failure in CI

  - To fix the nios member module params

  - To fix the nios_zone module idempotency failure

  - add terminal initial prompt for initial connection

  - allow include_role to work with ansible command

  - allow python_requirements_facts to report on
    dependencies containing dashes

  - asa_config fix

  - azure_rm_roledefinition - fix a small error in build
    scope.

  - azure_rm_virtualnetworkpeering - fix cross subscriptions
    virtual network peering.

  - cgroup_perf_recap - When not using file_per_task, make
    sure we don't prematurely close the perf files

  - display underlying error when reporting an invalid
    ``tasks:`` block.

  - dnf - fix wildcard matching for state: absent

  - docker connection plugin - accept version ``dev`` as
    'newest version' and print warning.

  - docker_container - ``oom_killer`` and ``oom_score_adj``
    options are available since docker-py 1.8.0, not 2.0.0
    as assumed by the version check.

  - docker_container - fix network creation when
    ``networks_cli_compatible`` is enabled.

  - docker_container - use docker API's ``restart`` instead
    of ``stop``/``start`` to restart a container.

  - docker_image - if ``build`` was not specified, the wrong
    default for ``build.rm`` is used.

  - docker_image - if ``nocache`` set to ``yes`` but not
    ``build.nocache``, the module failed.

  - docker_image - module failed when ``source: build`` was
    set but ``build.path`` options not specified.

  - docker_network module - fix idempotency when using
    ``aux_addresses`` in ``ipam_config``.

  - ec2_instance - make Name tag idempotent

  - eos: don't fail modules without become set, instead show
    message and continue

  - eos_config: check for session support when asked to
    'diff_against: session'

  - eos_eapi: fix idempotency issues when vrf was
    unspecified.

  - fix bugs for ce - more info see

  - fix incorrect uses of to_native that should be to_text
    instead.

  - hcloud_volume - Fix idempotency when attaching a server
    to a volume.

  - ibm_storage - Added a check for null fields in
    ibm_storage utils module.

  - include_tasks - whitelist ``listen`` as a valid keyword

  - k8s - resource updates applied with force work correctly
    now

  - keep results subset also when not no_log.

  - meraki_switchport - improve reliability with native VLAN
    functionality.

  - netapp_e_iscsi_target - fix netapp_e_iscsi_target chap
    secret size and clearing functionality

  - netapp_e_volumes - fix workload profileId indexing when
    no previous workload tags exist on the storage array.

  - nxos_acl some platforms/versions raise when no ACLs are
    present

  - nxos_facts fix
    <https://github.com/ansible/ansible/pull/57009>

  - nxos_file_copy fix passwordless workflow

  - nxos_interface Fix admin_state check for n6k

  - nxos_snmp_traps fix group all for N35 platforms

  - nxos_snmp_user fix platform fixes for get_snmp_user

  - nxos_vlan mode idempotence bug

  - nxos_vlan vlan names containing regex ctl chars should
    be escaped

  - nxos_vtp_* modules fix n6k issues

  - openssl_certificate - fix private key passphrase
    handling for ``cryptography`` backend.

  - openssl_pkcs12 - fixes crash when private key has a
    passphrase and the module is run a second time.

  - os_stack - Apply tags conditionally so that the module
    does not throw up an error when using an older distro of
    openstacksdk

  - pass correct loading context to persistent connections
    other than local

  - pkg_mgr - Ansible 2.8.0 failing to install yum packages
    on Amazon Linux

  - postgresql - added initial SSL related tests

  - postgresql - added missing_required_libs, removed excess
    param mapping

  - postgresql - move connect_to_db and get_pg_version into
    module_utils/postgres.py
    (https://github.com/ansible/ansible/pull/55514)

  - postgresql_db - add note to the documentation about
    state dump and the incorrect rc
    (https://github.com/ansible/ansible/pull/57297)

  - postgresql_db - fix for postgresql_db fails if stderr
    contains output

  - postgresql_ping - fixed a typo in the module
    documentation

  - preserve actual ssh error when we cannot connect.

  - route53_facts - the module did not advertise check mode
    support, causing it not to be run in check mode.

  - sysctl: the module now also checks the output of STDERR
    to report if values are correctly set
    (https://github.com/ansible/ansible/pull/55695)

  - ufw - correctly check status when logging is off

  - uri - always return a value for status even during
    failure

  - urls - Handle redirects properly for IPv6 address by not
    splitting on ``:`` and rely on already parsed hostname
    and port values

  - vmware_vm_facts - fix the support with regular ESXi

  - vyos_interface fix
    <https://github.com/ansible/ansible/pull/57169>

  - we don't really need to template vars on definition as
    we do this on demand in templating.

  - win_acl - Fix qualifier parser when using UNC paths -

  - win_hostname - Fix non netbios compliant name handling

  - winrm - Fix issue when attempting to parse CLIXML on
    send input failure

  - xenserver_guest - fixed an issue where VM whould be
    powered off even though check mode is used if
    reconfiguration requires VM to be powered off.

  - xenserver_guest - proper error message is shown when
    maximum number of network interfaces is reached and
    multiple network interfaces are added at once.

  - yum - Fix false error message about autoremove not being
    supported

  - yum - fix failure when using ``update_cache`` standalone

  - yum - handle special '_none_' value for proxy in
    yum.conf and .repo files

Update to version 2.8.0

Major changes :

  - Experimental support for Ansible Collections and content
    namespacing - Ansible content can now be packaged in a
    collection and addressed via namespaces. This allows for
    easier sharing, distribution, and installation of
    bundled modules/roles/plugins, and consistent rules for
    accessing specific content via namespaces.

  - Python interpreter discovery - The first time a Python
    module runs on a target, Ansible will attempt to
    discover the proper default Python interpreter to use
    for the target platform/version (instead of immediately
    defaulting to /usr/bin/python). You can override this
    behavior by setting ansible_python_interpreter or via
    config. (see
    https://github.com/ansible/ansible/pull/50163)

  - become - The deprecated CLI arguments for --sudo,
    --sudo-user,

    --ask-sudo-pass, -su, --su-user, and --ask-su-pass have
    been removed, in favor of the more generic --become,
    --become-user, --become-method, and

    --ask-become-pass.

  - become - become functionality has been migrated to a
    plugin architecture, to allow customization of become
    functionality and 3rd party become methods
    (https://github.com/ansible/ansible/pull/50991)

  - addresses CVE-2018-16859, CVE-2018-16876, CVE-2019-3828,
    CVE-2018-16837

For the full changelog see /usr/share/doc/packages/ansible/changelogs
or online:
https://github.com/ansible/ansible/blob/stable-2.8/changelogs/CHANGELO
G-v2.8.rst"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126503"
  );
  # https://github.com/ansible/ansible/blob/stable-2.8/changelogs/CHANGELOG-v2.8.rst
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/50163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/50991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/55514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/55695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/57009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/57169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/57297"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ansible package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ansible");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0|SUSE15\.1|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"ansible-2.8.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ansible-2.8.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ansible-2.8.1-12.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible");
}
