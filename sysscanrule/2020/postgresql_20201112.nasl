##
# 
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
##

include('compat.inc');

if (description)
{
  script_id(144060);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/16");

  script_cve_id("CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696");
  script_xref(name:"IAVB", value:"2020-B-0069");

  script_name(english:"PostgreSQL 9.5.x < 9.5.24 / 9.6.x < 9.6.20 / 10.x < 10.15 / 11.x < 11.10 / 12.x < 12.5 / 13.x < 13.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.5 prior to 9.5.24, 9.6 prior to 9.6.20, 10 prior to 10.15,
11 prior to 11.10, 12 prior to 12.5, or 13 prior to 13.1. As such, it is potentially affected by multiple
vulnerabilities :
  - Multiple features escape security restricted operation sandbox (CVE-2020-25695)
  - Reconnection can downgrade connection security settings (CVE-2020-25694)
  - psql's gset allows overwriting specially treated variables (CVE-2020-25696)
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-131-125-1110-1015-9620-and-9524-released-2111/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccdf09f5");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25695");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25694");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25696");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 9.5.24 / 9.6.20 / 10.15 / 11.10 / 12.5 / 13.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include('vcf.inc');
include('backport.inc');

app = 'PostgreSQL';
port = get_service(svc:'postgresql', default:5432, exit_on_fail:TRUE);
kb_base = 'database/' + port + '/postgresql/';
kb_ver = kb_base + 'version';
get_kb_item_or_exit(kb_ver);

kb_backport = NULL;
source = get_kb_item_or_exit(kb_base + 'source');
get_backport_banner(banner:source);
if (backported) kb_backport = kb_base + 'backported';

app_info = vcf::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_backport:kb_backport, service:TRUE);

#  9.5.24 / 9.6.20 / 10.15 / 11.10 / 12.5 / 13.1
constraints = [
  { 'min_version' : '9.5', 'fixed_version' : '9.5.24' },
  { 'min_version' : '9.6', 'fixed_version' : '9.6.20' },
  { 'min_version' : '10', 'fixed_version' : '10.15' },
  { 'min_version' : '11', 'fixed_version' : '11.10' },
  { 'min_version' : '12', 'fixed_version' : '12.5' },
  { 'min_version' : '13', 'fixed_version' : '13.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);