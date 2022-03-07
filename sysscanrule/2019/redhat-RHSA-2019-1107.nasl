#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1107. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124840);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/12 10:41:31");

  script_cve_id("CVE-2018-11307", "CVE-2018-12022", "CVE-2018-12023", "CVE-2018-14642", "CVE-2018-14720", "CVE-2018-14721", "CVE-2019-3805", "CVE-2019-3894");
  script_xref(name:"RHSA", value:"2019:1107");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2019:1107)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 7.2 for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform 7 is a platform for Java
applications based on JBoss Application Server 7.

This release of Red Hat JBoss Enterprise Application Platform 7.2.1
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 7.2.0, and includes bug fixes and enhancements. Refer to the
Red Hat JBoss Enterprise Application Platform 7.2.1 Release Notes for
information on the most significant bug fixes and enhancements
included in this release.

Security Fix(es) :

* jackson-databind: Potential information exfiltration with default
typing, serialization gadget from MyBatis (CVE-2018-11307)

* jackson-databind: improper polymorphic deserialization of types from
Jodd-db library (CVE-2018-12022)

* jackson-databind: improper polymorphic deserialization of types from
Oracle JDBC driver (CVE-2018-12023)

* undertow: Infoleak in some circumstances where Undertow can serve
data from a random buffer (CVE-2018-14642)

* jackson-databind: exfiltration/XXE in some JDK classes
(CVE-2018-14720)

* jackson-databind: server-side request forgery (SSRF) in axis2-jaxws
class (CVE-2018-14721)

* wildfly: Race condition on PID file allows for termination of
arbitrary processes by local users (CVE-2019-3805)

* wildfly: wrong SecurityIdentity for EE concurrency threads that are
reused (CVE-2019-3894)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-11307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-12022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-12023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3894"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-dto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hornetq-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hqclient-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jdbc-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-journal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-byte-buddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-bug986");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-asyncclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-v53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-istack-commons-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-istack-commons-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-el-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-genericjms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly11.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly12.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly12.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly13.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbosstxbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbossxts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-simple-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-wildfly8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client-microprofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson2-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jose-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-binding-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-jastow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-yasson");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1107";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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

  if (! (rpm_exists(release:"RHEL6", rpm:"eap7-jboss"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-cli-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-commons-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-core-client-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-dto-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-hornetq-protocol-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-hqclient-protocol-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-jdbc-store-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-jms-client-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-jms-server-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-journal-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-native-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-ra-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-selector-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-server-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-service-extensions-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-tools-2.6.3-5.redhat_00020.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-commons-lang-3.8.0-1.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-3.2.7-1.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-rt-3.2.7-1.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-services-3.2.7-1.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-tools-3.2.7-1.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-xjc-utils-3.2.3-2.redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eap7-artemis-native-2.6.3-15.redhat_00020.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eap7-artemis-native-wildfly-2.6.3-15.redhat_00020.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-byte-buddy-1.9.5-1.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-boolean-3.2.3-2.redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-bug986-3.2.3-2.redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-dv-3.2.3-2.redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-runtime-3.2.3-2.redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-ts-3.2.3-2.redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-dom4j-2.1.1-2.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-5.3.9-2.Final_redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-core-5.3.9-2.Final_redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-entitymanager-5.3.9-2.Final_redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-envers-5.3.9-2.Final_redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-java8-5.3.9-2.Final_redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-httpcomponents-asyncclient-4.1.4-1.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-cachestore-jdbc-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-cachestore-remote-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-client-hotrod-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-commons-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-core-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-hibernate-cache-commons-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-hibernate-cache-spi-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-hibernate-cache-v53-9.3.6-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-common-api-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-common-impl-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-common-spi-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-core-api-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-core-impl-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-deployers-common-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-jdbc-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-validator-1.4.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-istack-commons-runtime-3.0.7-2.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-istack-commons-tools-3.0.7-2.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-annotations-2.9.8-2.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-core-2.9.8-2.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-databind-2.9.8-2.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-datatype-jdk8-2.9.8-1.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-datatype-jsr310-2.9.8-1.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-jaxrs-base-2.9.8-2.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-jaxrs-json-provider-2.9.8-2.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-module-jaxb-annotations-2.9.8-1.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-modules-base-2.9.8-1.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-modules-java8-2.9.8-1.redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jberet-1.3.2-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jberet-core-1.3.2-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ejb-client-4.0.15-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-el-api_3.0_spec-1.0.13-2.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-genericjms-2.0.1-2.Final_redhat_00002.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-logmanager-2.1.7-3.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-remoting-jmx-3.0.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-security-negotiation-3.0.5-2.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-cli-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-core-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap6.4-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap6.4-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.0-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.0-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.1-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.1-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.0-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.0-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.1-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.1-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly11.0-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly11.0-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly12.0-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly12.0-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly13.0-server-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly8.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly8.2-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly9.0-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly9.0-to-eap7.2-1.3.0-7.Final_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-compensations-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jbosstxbridge-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jbossxts-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jts-idlj-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jts-integration-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-api-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-bridge-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-integration-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-util-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-txframework-5.9.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-api-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-bindings-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-common-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-config-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-federation-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-idm-api-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-idm-impl-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-idm-simple-schema-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-impl-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketlink-wildfly8-2.5.5-16.SP12_redhat_4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-atom-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-cdi-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-client-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-client-microprofile-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-crypto-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jackson-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jackson2-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jaxb-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jaxrs-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jettison-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jose-jwt-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jsapi-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-json-binding-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-json-p-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-multipart-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-rxjava2-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-spring-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-validator-provider-11-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-yaml-provider-3.6.1-4.SP3_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-sun-istack-commons-3.0.7-2.redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-undertow-2.0.19-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-undertow-jastow-2.0.7-2.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-undertow-server-1.2.4-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-7.2.1-6.GA_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-elytron-1.6.2-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-elytron-tool-1.4.1-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-client-common-1.0.13-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-ejb-client-1.0.13-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-naming-client-1.0.13-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-transaction-client-1.0.13-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-javadocs-7.2.1-6.GA_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-modules-7.2.1-6.GA_redhat_00004.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-transaction-client-1.1.3-1.Final_redhat_00001.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-yasson-1.0.2-1.redhat_00001.1.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-activemq-artemis / eap7-activemq-artemis-cli / etc");
  }
}
