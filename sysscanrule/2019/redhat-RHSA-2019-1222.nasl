#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1222. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125052);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/14 17:32:44");

  script_cve_id("CVE-2016-6346", "CVE-2018-10917", "CVE-2018-14664", "CVE-2018-16861", "CVE-2018-16887", "CVE-2019-3891");
  script_xref(name:"RHSA", value:"2019:1222");

  script_name(english:"RHEL 7 : Satellite Server (RHSA-2019:1222)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Satellite 6.5 for RHEL 7 is now available containing security
fixes, bug fixes, and enhancements.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Satellite is a systems management tool for Linux-based
infrastructure. It allows for provisioning, remote management, and
monitoring of multiple Linux deployments with a single centralized
tool.

Security Fix(es) :

* RESTEasy: Abuse of GZIPInterceptor in RESTEasy can lead to denial of
service attack (CVE-2016-6346)

* pulp: Improper path parsing leads to overwriting of iso repositories
(CVE-2018-10917)

* foreman: Persisted XSS on all pages that use breadcrumbs
(CVE-2018-14664)

* foreman: stored XSS in success notification after entity creation
(CVE-2018-16861)

* katello: stored XSS in subscriptions and repositories pages
(CVE-2018-16887)

* candlepin: credentials exposure through log files (CVE-2019-3891)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

This update also fixes several bugs and adds various enhancements.
Documentation for these changes is available from the Release Notes
document linked to in the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_satellite/6.5/html/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-16861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-16887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3891"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SOAPpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-insights-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat-tftpboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-rackspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-telemetry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hfsplus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hfsplus-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-client-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kobo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmodulemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmodulemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebsockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liquibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:livecd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_xsendfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_xsendfile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ostree-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-mmvstatsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-admin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-maintenance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetlabs-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-billiard-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-blinker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-crane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-flask");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-fpconst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-imgcreate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-isodate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-itsdangerous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-kid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-mongoengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nectar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oauth2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-okaara");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-client-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-docker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-integrity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-oid_validation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-ostree-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-repoauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-streamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-semantic_version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-simplejson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-simplejson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-twisted-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-twisted-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-werkzeug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zope-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zope-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-amqp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-billiard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-celery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-kombu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-vine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-linearstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-access-insights-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:repoview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhel8-kickstart-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-concurrent-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday_middleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_wizards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-newt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rb-inotify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rubyipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dhcp_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dhcp_remote_isc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery_image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dns_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_remote_execution_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-debug-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-arel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-coffee-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-coffee-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-coffee-script-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-concurrent-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-crass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-erubi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-execjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-globalid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-loofah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-marcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-method_source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mime-types-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mimemagic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mini_mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mini_portile2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mustermann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-nio4r");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-nio4r-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-nokogiri-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rack-protection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rails-dom-testing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rails-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sprockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sprockets-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sqlite3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-thor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-thread_safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-turbolinks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-websocket-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-websocket-driver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-websocket-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord-session_store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-algebrick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ancestry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-anemone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-angular-rails-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-audited");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-autoparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-awesome_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-bastion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-concurrent-ruby-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-css_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deacon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deep_cloneable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-diffy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-docker-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-domain_name");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-extlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-digitalocean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-google");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-rackspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-vsphere");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-xenserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-formatador");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-friendly_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-get_process_mem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gettext_i18n_rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-google-api-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gssapi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-jgrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-launchy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ldap_fluff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ssh-krb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt-engine-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt-engine-sdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt_provision_plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-parse-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-polyglot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-prometheus-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-qpid_messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-qpid_messaging-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-quantile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rabl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-jsonp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rails-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rainbow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rbovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rbvmomi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-record_tag_helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redhat_access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redhat_access_lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-responders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-retriable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-roadie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-roadie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-robotex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-runcible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-safemode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-scoped_search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-secure_headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sequel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-signet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dynflow_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sshkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-statsd-instrument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-trollop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf_ext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode-display_width");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-validates_lengths_from_database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-webpack-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-wicked");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-will_paginate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-x-editable-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1222";
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
  flag = 0;

  if (! (rpm_exists(release:"RHEL7", rpm:"katello-agent-3.3"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL7", reference:"SOAPpy-0.11.6-17.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ansiblerole-insights-client-1.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"candlepin-2.5.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"candlepin-selinux-2.5.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"createrepo_c-0.7.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"createrepo_c-debuginfo-0.7.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"createrepo_c-libs-0.7.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-bootloaders-redhat-201801241201-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-bootloaders-redhat-tftpboot-201801241201-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-cli-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-compute-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-debug-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-discovery-image-3.5.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ec2-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-gce-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-installer-1.20.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-installer-katello-3.10.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-journald-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-libvirt-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-openstack-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ovirt-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-postgresql-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-proxy-1.20.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-proxy-content-3.10.0-0.6.rc1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-rackspace-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-selinux-1.20.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-telemetry-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-vmware-1.20.1.34-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hfsplus-tools-332.14-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hfsplus-tools-debuginfo-332.14-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-3.10.0-0.6.rc1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-certs-tools-2.4.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-client-bootstrap-1.7.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-common-3.10.0-0.6.rc1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-debug-3.10.0-0.6.rc1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-installer-base-3.10.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-selinux-3.0.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-service-3.10.0-0.6.rc1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kobo-0.5.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libmodulemd-1.6.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libmodulemd-debuginfo-1.6.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libsolv-0.6.34-2.pulp.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libsolv-debuginfo-0.6.34-2.pulp.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libwebsockets-2.4.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libwebsockets-debuginfo-2.4.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"liquibase-3.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"livecd-tools-20.4-1.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_passenger-4.0.18-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_xsendfile-0.12-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_xsendfile-debuginfo-0.12-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ostree-2017.1-2.atomic.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ostree-debuginfo-2017.1-2.atomic.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pcp-mmvstatsd-0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-admin-client-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-docker-admin-extensions-3.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-docker-plugins-3.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-katello-1.0.2-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-maintenance-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-ostree-admin-extensions-1.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-ostree-plugins-1.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-admin-extensions-2.18.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-plugins-2.18.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-tools-2.18.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-rpm-admin-extensions-2.18.1.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-rpm-plugins-2.18.1.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-selinux-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-server-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"puppet-agent-5.5.12-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"puppet-agent-oauth-0.5.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"puppet-foreman_scap_client-0.3.19-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"puppetlabs-stdlib-4.25.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"puppetserver-5.3.6-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-billiard-debuginfo-3.5.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-blinker-1.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-bson-3.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-crane-3.3.0-0.1.rc.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-flask-0.10.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-fpconst-0.7.3-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gnupg-0.3.7-1.el7ui")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gofer-2.12.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gofer-qpid-2.12.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-imgcreate-20.4-1.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-isodate-0.5.0-5.pulp.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-itsdangerous-0.23-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-kid-0.9.6-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-mongoengine-0.10.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-nectar-1.5.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-oauth2-1.5.211-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-okaara-1.0.32-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-bindings-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-client-lib-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-common-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-docker-common-3.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-integrity-2.18.1.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-oid_validation-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-ostree-common-1.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-puppet-common-2.18.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-repoauth-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-rpm-common-2.18.1.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-streamer-2.18.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-pymongo-3.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-pymongo-debuginfo-3.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-pymongo-gridfs-3.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-qpid-1.35.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-qpid-proton-0.26.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-qpid-qmf-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-saslwrapper-0.22-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-semantic_version-2.2.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-simplejson-3.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-simplejson-debuginfo-3.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-twisted-core-12.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-twisted-core-debuginfo-12.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-twisted-web-12.1.0-5.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-werkzeug-0.9.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-zope-interface-4.0.5-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-zope-interface-debuginfo-4.0.5-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-amqp-2.2.2-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python2-billiard-3.5.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-celery-4.0.2-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-django-1.11.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-kombu-4.0.2-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python2-solv-0.6.34-2.pulp.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-vine-1.1.3-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-client-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-client-devel-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-debuginfo-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-server-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-server-linearstore-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-debuginfo-1.5.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-router-1.5.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"qpid-dispatch-tools-1.5.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-c-0.26.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.26.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-qmf-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", reference:"qpid-tools-1.36.0-24.el7amq")) flag++;
  if (rpm_check(release:"RHEL7", reference:"redhat-access-insights-puppet-0.0.9-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"repoview-0.6.6-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rhel8-kickstart-setup-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-ansi-1.4.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-bundler_ext-0.4.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-clamp-1.1.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-concurrent-ruby-1.0.3-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-facter-2.4.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-faraday-0.9.1-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-faraday_middleware-0.10.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fast_gettext-1.1.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-ffi-1.4.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-ffi-debuginfo-1.4.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-foreman_scap_client-0.4.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-gssapi-1.1.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-hashie-2.0.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-highline-1.7.8-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-infoblox-2.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-jwt-1.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo-2.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo_parsers-0.1.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo_wizards-0.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-little-plugger-1.1.3-22.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-logging-2.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-mime-types-1.19-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-multi_json-1.12.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-multipart-post-1.2.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-netrc-0.7.7-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-newt-0.9.6-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-newt-debuginfo-0.9.6-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-oauth-0.5.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-openscap-0.4.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-4.0.18-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-debuginfo-4.0.18-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-native-4.0.18-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-native-libs-4.0.18-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-powerbar-1.0.17-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rake-0.9.2.2-41.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rb-inotify-0.9.7-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rest-client-1.6.7-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-rkerberos-0.1.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-rkerberos-debuginfo-0.1.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rsec-0.4.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rubyipmi-0.10.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_ansible-2.0.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_dhcp_infoblox-0.0.14-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_dhcp_remote_isc-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_discovery-1.0.4-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_discovery_image-1.0.9-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_dns_infoblox-0.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_dynflow-0.2.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_openscap-0.7.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_pulp-1.3.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_remote_execution_ssh-0.2.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-tilt-1.3.7-2.git.0.3b416c9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"saslwrapper-0.22-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"saslwrapper-debuginfo-0.22-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-6.5.0-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-capsule-6.5.0-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-cli-6.5.0-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-common-6.5.0-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-debug-tools-6.5.0-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-installer-6.5.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-actioncable-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-actionmailer-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-actionpack-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-actionview-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-activejob-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-activemodel-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-activerecord-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-activestorage-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-activesupport-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-arel-9.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-builder-3.2.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-coffee-rails-4.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-coffee-script-2.4.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-coffee-script-source-1.12.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-concurrent-ruby-1.0.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-crass-1.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-erubi-1.7.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-execjs-2.7.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-globalid-0.4.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-i18n-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-loofah-2.2.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mail-2.7.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-marcel-0.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-method_source-0.9.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mime-types-3.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mime-types-data-3.2018.0812-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mimemagic-0.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mini_mime-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mini_portile2-2.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-multi_json-1.13.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-mustermann-1.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-nio4r-2.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-nio4r-debuginfo-2.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-nokogiri-1.8.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-nokogiri-debuginfo-1.8.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-rack-2.0.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-rack-protection-2.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-rack-test-1.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-rails-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-rails-dom-testing-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-rails-html-sanitizer-1.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-railties-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-sinatra-2.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-sprockets-3.7.2-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-sprockets-rails-3.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-sqlite3-1.3.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-sqlite3-debuginfo-1.3.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-thor-0.20.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-thread_safe-0.3.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-tilt-2.0.8-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-turbolinks-2.5.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-tzinfo-1.2.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-websocket-driver-0.7.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-rubygem-websocket-driver-debuginfo-0.7.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-ror52-rubygem-websocket-extensions-0.1.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-ror52-runtime-1.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-activerecord-import-1.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-activerecord-session_store-1.1.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-addressable-2.3.6-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-algebrick-0.7.3-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-ancestry-3.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-anemone-0.7.2-20.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-angular-rails-templates-1.0.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-apipie-bindings-0.2.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-apipie-params-0.0.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-apipie-rails-0.5.14-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-audited-4.7.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-autoparse-0.3.3-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-awesome_print-1.8.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-bastion-6.1.23-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-bundler_ext-0.4.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-clamp-1.1.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-concurrent-ruby-edge-0.2.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-css_parser-1.4.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-daemons-1.2.3-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-deacon-1.0.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-deep_cloneable-2.3.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-deface-1.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-diffy-3.0.1-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-docker-api-1.28.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-domain_name-0.5.20160310-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-dynflow-1.1.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-excon-0.58.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-extlib-0.9.16-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-facter-2.4.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-faraday-0.9.1-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fast_gettext-1.4.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-ffi-1.4.0-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-ffi-debuginfo-1.4.0-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-1.42.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-aws-1.3.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-core-1.45.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-digitalocean-0.3.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-google-0.1.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-json-1.0.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-libvirt-0.4.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-openstack-0.1.25-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-ovirt-1.1.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-rackspace-0.1.4-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-vsphere-2.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-xenserver-0.2.3-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-fog-xml-0.1.2-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman-tasks-0.14.4.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman-tasks-core-0.2.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_ansible-2.2.14-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_ansible_core-2.1.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_bootdisk-14.0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_discovery-14.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_docker-4.1.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_hooks-0.3.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_openscap-0.11.5.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_remote_execution-1.6.7-19.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_remote_execution_core-1.1.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_templates-6.0.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_theme_satellite-3.0.1.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_virt_who_configure-0.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-formatador-0.2.1-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-friendly_id-5.2.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-get_process_mem-0.2.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-gettext_i18n_rails-1.2.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-git-1.2.5-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-google-api-client-0.8.2-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-gssapi-1.2.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli-0.15.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_csv-2.3.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman-0.15.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_admin-0.0.8-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_ansible-0.1.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_bootdisk-0.1.3.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_discovery-1.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_docker-0.0.6.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_openscap-0.1.6-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_remote_execution-0.1.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_tasks-0.0.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_templates-0.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_virt_who_configure-0.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_katello-0.16.0.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hashie-3.6.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-highline-1.7.8-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-http-cookie-1.0.2-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-ipaddress-0.8.0-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-jgrep-1.3.3-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-journald-logger-2.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-journald-native-1.0.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-journald-native-debuginfo-1.0.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-jwt-1.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-katello-3.10.0.46-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-launchy-2.4.3-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-ldap_fluff-0.4.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-little-plugger-1.1.3-23.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-locale-2.0.9-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-logging-2.2.2-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-logging-journald-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-multipart-post-1.2.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-net-ldap-0.15.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-net-ping-2.0.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-net-scp-1.2.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-net-ssh-4.0.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-net-ssh-krb-0.4.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-netrc-0.11.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-oauth-0.5.4-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-ovirt-engine-sdk-4.2.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-ovirt-engine-sdk-debuginfo-4.2.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-ovirt_provision_plugin-2.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-parse-cron-0.1.4-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-passenger-4.0.18-25.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-passenger-debuginfo-4.0.18-25.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-passenger-native-4.0.18-25.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-passenger-native-libs-4.0.18-25.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-pg-0.21.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-pg-debuginfo-0.21.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-polyglot-0.3.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-powerbar-2.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-prometheus-client-0.7.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-qpid_messaging-1.36.0-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-qpid_messaging-debuginfo-1.36.0-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-quantile-0.2.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rabl-0.13.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rack-jsonp-1.3.1-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rails-i18n-5.1.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rainbow-2.2.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rbovirt-0.1.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rbvmomi-1.10.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-record_tag_helper-1.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-redhat_access-2.2.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-redhat_access_lib-1.1.4-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-responders-2.4.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-rest-client-2.0.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-retriable-1.4.1-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-roadie-3.2.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-roadie-rails-1.3.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-robotex-1.0.0-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-ruby-libvirt-0.7.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-ruby-libvirt-debuginfo-0.7.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-ruby2ruby-2.4.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-ruby_parser-3.10.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-runcible-2.11.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-safemode-1.3.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-scoped_search-4.1.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-secure_headers-6.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-sequel-5.7.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-sexp_processor-4.10.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-signet-0.6.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-smart_proxy_dynflow_core-0.2.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-sshkey-1.9.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-statsd-instrument-2.1.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-trollop-2.1.2-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-unf-0.1.3-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unf_ext-0.0.6-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unf_ext-debuginfo-0.0.6-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unicode-0.4.4.1-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-rubygem-unicode-debuginfo-0.4.4.1-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-unicode-display_width-1.0.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-validates_lengths_from_database-0.5.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-webpack-rails-0.9.8-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-wicked-1.3.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-will_paginate-3.1.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-x-editable-rails-1.5.5-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tfm-runtime-5.0-3.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SOAPpy / ansiblerole-insights-client / candlepin / etc");
  }
}
