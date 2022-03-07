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
  script_id(149850);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id("CVE-2021-32027", "CVE-2021-32028", "CVE-2021-32029");

  script_name(english:"PostgreSQL 9.6.x < 9.6.22 / 10.x < 10.17 / 11.x < 11.12 / 12.x < 12.7 / 13.x < 13.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.6 prior to 9.6.22, 10 prior to 10.17, 11 prior to 11.12, 12
prior to 12.7, or 13 prior to 13.3. As such, it is potentially affected by multiple vulnerabilities :

  - Buffer overrun from integer overflow in array subscripting calculations (CVE-2021-32027)

  - Memory disclosure in INSERT ... ON CONFLICT ... DO UPDATE (CVE-2021-32028)

  - Memory disclosure in partitioned-table UPDATE ... RETURNING (CVE-2021-32029)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-133-127-1112-1017-and-9622-released-2210/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d682c4df");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/support/security/CVE-2021-32029/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/support/security/CVE-2021-32028/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/support/security/CVE-2021-32027/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 9.6.22 / 10.17 / 11.12 / 12.7 / 13.3 or later");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432, "installed_sw/PostgreSQL");

  exit(0);
}

include('vcf_extras_postgresql.inc');

var app = 'PostgreSQL';
var win_local = TRUE;

if (!get_kb_item('SMB/Registry/Enumerated'))
  win_local = FALSE;

var port = get_service(svc:'postgresql', default:5432);
var kb_base = 'database/' + port + '/postgresql/';
var kb_ver = NULL;
var kb_path = kb_base + 'version';
var ver = get_kb_item(kb_path);
if (!empty_or_null(ver)) kb_ver = kb_path;

app_info = vcf::postgresql::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_base:kb_base, win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:2);

#  9.6.22 / 10.17 / 11.12 / 12.7 / 13.3
constraints = [
  { 'min_version' : '9.6', 'fixed_version' : '9.6.22' },
  { 'min_version' : '10', 'fixed_version' : '10.17' },
  { 'min_version' : '11', 'fixed_version' : '11.12' },
  { 'min_version' : '12', 'fixed_version' : '12.7' },
  { 'min_version' : '13', 'fixed_version' : '13.3' }
];

vcf::postgresql::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
