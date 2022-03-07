#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1223. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125053);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/22 17:37:24");

  script_cve_id("CVE-2019-3845");
  script_xref(name:"RHSA", value:"2019:1223");

  script_name(english:"RHEL 6 / 7 / 8 : Red Hat Satellite Tools (RHSA-2019:1223)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Satellite Tools 6.5.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Satellite is a systems management tool for Linux-based
infrastructure. It allows for provisioning, remote management, and
monitoring of multiple Linux deployments with a single centralized
tool.

This update provides the Satellite 6.5 Tools repositories. For the
full list of new features provided by Satellite 6.5, see the Release
Notes linked to in the references section. See the Satellite 6
Installation Guide for detailed instructions on how to install a new
Satellite 6.5 environment, or the Satellite 6 Upgrading and Updating
guide for detailed instructions on how to upgrade from prior versions
of Satellite 6.

All users who require Satellite version 6.5 are advised to install
these new packages.

Security Fix(es) :

* qpid-dispatch-router: QMF methods exposed to goferd via qdrouterd
(CVE-2019-3845)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_satellite/6.5/html/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3845"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3845");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-host-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-host-tools-fact-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-host-tools-tracer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap-scanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-argcomplete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-hashlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-hashlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-isodate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psutil-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psutil-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-agent-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-manifest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-uuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-beautifulsoup4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-tracer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-beautifulsoup4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-gofer-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-psutil-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qpid-proton-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-tracer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mime-types-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-awesome_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-domain_name");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_csv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http-cookie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf_ext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode-display_width");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tracer-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(5|6|7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x / 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1223";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  if (! (rpm_exists(release:"RHEL6", rpm:"satellite-6.5") || rpm_exists(release:"RHEL7", rpm:"satellite-6.5") || rpm_exists(release:"RHEL8", rpm:"satellite-6.5"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite 6.5");

  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"gofer-2.11.9-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-agent-3.5.0-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-host-tools-3.5.0-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-host-tools-fact-plugin-3.5.0-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"openscap-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"openscap-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"openscap-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"openscap-debuginfo-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"openscap-debuginfo-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"openscap-debuginfo-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"openscap-scanner-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"openscap-scanner-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"openscap-scanner-1.2.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-rpm-handlers-2.18.1.5-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"puppet-agent-5.5.12-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"puppet-agent-5.5.12-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-2.11.9-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-proton-2.11.9-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-isodate-0.5.0-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-agent-lib-2.18.1.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-common-2.18.1.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-rpm-common-2.18.1.5-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-qpid-proton-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-qpid-proton-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-qpid-proton-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-proton-c-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"qpid-proton-c-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-c-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-proton-debuginfo-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"qpid-proton-debuginfo-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.16.0-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-foreman_scap_client-0.4.5-1.el6sat")) flag++;
  if (rpm_exists(rpm:"rubygem-json-1.4", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"i686", reference:"rubygem-json-1.4.6-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-1.4", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"s390x", reference:"rubygem-json-1.4.6-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-1.4", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-1.4.6-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-debuginfo-1.4", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"i686", reference:"rubygem-json-debuginfo-1.4.6-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-debuginfo-1.4", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"s390x", reference:"rubygem-json-debuginfo-1.4.6-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-debuginfo-1.4", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-debuginfo-1.4.6-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygems-1.3", release:"RHEL6") && rpm_check(release:"RHEL6", sp:"6", reference:"rubygems-1.3.7-5.el6")) flag++;
  if (rpm_exists(rpm:"rubygems-1.3", release:"RHEL6") && rpm_check(release:"RHEL6", sp:"4", reference:"rubygems-1.3.7-5.el6")) flag++;
  if (rpm_exists(rpm:"rubygems-1.3", release:"RHEL6") && rpm_check(release:"RHEL6", sp:"5", reference:"rubygems-1.3.7-5.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"foreman-cli-1.20.1.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gofer-2.12.5-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-agent-3.5.0-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-host-tools-3.5.0-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-host-tools-fact-plugin-3.5.0-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-host-tools-tracer-3.5.0-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-tools-2.18.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"pulp-rpm-handlers-2.18.1.5-1.el5")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"puppet-agent-5.5.12-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-argcomplete-1.7.0-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gofer-2.12.5-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gofer-proton-2.12.5-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-hashlib-20081119-7.el5sat")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-hashlib-debuginfo-20081119-7.el5sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-isodate-0.5.0-5.pulp.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-psutil-5.0.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-psutil-5.0.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-psutil-debuginfo-5.0.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-psutil-debuginfo-5.0.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"python-pulp-agent-lib-2.18.1.1-1.el5")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-common-2.18.1.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-manifest-2.18.1.5-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-puppet-common-2.18.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"python-pulp-rpm-common-2.18.1.5-1.el5")) flag++;
  if (sp == "2") {
    if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-qpid-proton-0.9-16.el5")) flag++;
    if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"qpid-proton-c-0.9-16.el5")) flag++;
    if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"qpid-proton-debuginfo-0.9-16.el5")) flag++;
  }
  else
  {
    if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-qpid-proton-0.26.0-3.el7")) flag++;
    if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"qpid-proton-c-0.26.0-3.el7")) flag++;
    if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"qpid-proton-debuginfo-0.26.0-3.el7")) flag++;
  }
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-qpid-proton-0.26.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"python-uuid-1.30-4.el5")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-beautifulsoup4-4.6.3-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-future-0.16.0-11.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-tracer-0.7.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-c-0.26.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.26.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-foreman_scap_client-0.4.5-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mime-types-3.2.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mime-types-data-3.2018.0812-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-multi_json-1.13.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-runtime-1.0-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-apipie-bindings-0.2.2-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-awesome_print-1.8.0-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-clamp-1.1.2-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-domain_name-0.5.20160310-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fast_gettext-1.4.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli-0.15.1.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_csv-2.3.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman-0.15.1.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_admin-0.0.8-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_ansible-0.1.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_bootdisk-0.1.3.3-5.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_discovery-1.0.0-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_docker-0.0.6.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_openscap-0.1.6-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_remote_execution-0.1.0-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_tasks-0.0.13-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_templates-0.1.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_virt_who_configure-0.0.3-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_katello-0.16.0.11-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hashie-3.6.0-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-highline-1.7.8-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-http-cookie-1.0.2-5.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-little-plugger-1.1.3-23.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-locale-2.0.9-13.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-logging-2.2.2-5.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-netrc-0.11.0-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-oauth-0.5.4-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-powerbar-2.0.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rest-client-2.0.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-unf-0.1.3-7.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unf_ext-0.0.6-9.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unf_ext-debuginfo-0.0.6-9.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unicode-0.4.4.1-6.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unicode-debuginfo-0.4.4.1-6.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-unicode-display_width-1.0.5-5.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-runtime-5.0-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tracer-common-0.7.1-2.el7sat")) flag++;

  if (rpm_check(release:"RHEL8", reference:"gofer-2.12.5-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"katello-agent-3.5.0-2.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"katello-host-tools-3.5.0-2.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"katello-host-tools-tracer-3.5.0-2.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"puppet-agent-5.5.12-1.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python-psutil-debugsource-5.0.1-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python-psutil-debugsource-5.0.1-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-beautifulsoup4-4.6.3-2.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-future-0.16.0-11.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-gofer-2.12.5-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-gofer-proton-2.12.5-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-psutil-5.0.1-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-psutil-5.0.1-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-psutil-debuginfo-5.0.1-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-psutil-debuginfo-5.0.1-3.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-qpid-proton-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-qpid-proton-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-qpid-proton-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-qpid-proton-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-tracer-0.7.1-2.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qpid-proton-c-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qpid-proton-c-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qpid-proton-c-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qpid-proton-c-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qpid-proton-cpp-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qpid-proton-cpp-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qpid-proton-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qpid-proton-debugsource-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qpid-proton-debugsource-0.26.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rubygem-foreman_scap_client-0.4.5-1.el8sat")) flag++;
  if (rpm_check(release:"RHEL8", reference:"tracer-common-0.7.1-2.el8sat")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "foreman-cli / gofer / katello-agent / katello-host-tools / etc");
  }
}
