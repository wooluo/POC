# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_mysql.inc
#
# Revision: 1.2

include('vcf.inc');
include('compat_shared.inc');

namespace vcf
{
  namespace mysql
  {
    function combined_get_app_info(variant, paranoid)
    {
      local_var app_info;
      
      if (empty_or_null(variant))
        variant = 'Community Server';

      if (empty_or_null(paranoid))
        paranoid = FALSE;

      app_info = vcf::combined_get_app_info(app:'MySQL Server');
      
      if ('Local' >!< app_info['Detection'] && report_paranoia < 2 && paranoid == FALSE)
        ::audit(AUDIT_POTENTIAL_VULN, 'MySQL Server');

      if (!empty_or_null(app_info['Variant']) && app_info['Variant'] != variant)
        exit(0, 'The server variant it not '+variant+'.');
      
      return app_info;
    }
  }
}