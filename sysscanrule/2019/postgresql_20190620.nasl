#
# (C) WebRAY Network Security, Inc.
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#

include("compat.inc");

if (description)
{
  script_id(126309);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/27 14:56:37");

  script_cve_id("CVE-2019-10164");
  script_bugtraq_id(108875);
  script_xref(name:"IAVB", value:"2019-B-0050");

  script_name(english:"PostgreSQL 10.x < 10.9 / 11.x < 11.4 Stack Overflow Vulnerability (CVE-2019-10164)");
  script_summary(english:"Checks version of PostgreSQL.");
  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a stack overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 10.x prior to 10.9 or 11.x prior to 11.4. As such, it is
potentially affected by a stack overflow vulnerability. Any authenticated user can overflow a stack-based buffer by
changing the user's own password to a purpose-crafted value.

Note that GizaNE has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1949/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10164");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 10.9 / 11.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10164");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include('global_settings.inc');
include('vcf.inc');
include('vcf_extras.inc');
include('backport.inc');

port = get_service(svc:'postgresql', default:5432, exit_on_fail:TRUE);
kb_base = 'database/' + port + '/postgresql/';

kb_ver = kb_base + 'version';
get_kb_item_or_exit(kb_ver);

kb_backport = NULL;
source = get_kb_item_or_exit(kb_base + 'source');
get_backport_banner(banner:source);
if (backported) kb_backport = kb_base + 'backported';

app_info = vcf::get_app_info(app:'PostgreSQL', port:port, kb_ver:kb_ver, kb_backport:kb_backport, service:TRUE);

#  10.9 / 11.4
constraints = [
  { 'min_version' : '10', 'fixed_version' : '10.9' },
  { 'min_version' : '11', 'fixed_version' : '11.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
