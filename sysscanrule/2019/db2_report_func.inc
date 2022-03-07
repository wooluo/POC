#
# (C) WebRAY Network Security, Inc.
#
# Revision:1.1
include("misc_func_nlib.inc");
include("spad_log_func.inc");

function report_db2(port, severity, platform_name, fixed_level, installed_level, instance, product, node, path, special_fix, special_installed, installed_version, fixed_version, info)
{
  local_var report = '';
  local_var path_encode;

  if(path)
  {
    path_encode = base64(str:path);
    path_encode = str_replace(string:path_encode, find:'=', replace:'$');
    spad_log(message:'encoded_path='+path_encode);
  }
  if(!product && port)
    product = get_kb_item("DB2/"+port+"/Product");
  if(!product && path)
    product = get_kb_item("DB2/"+path+"/Product");
  if(!product && path_encode)
    product = get_kb_item("DB2/"+path_encode+"/Product");
  if(!node && port)
    node = get_kb_item("DB2/"+port+"/Node");
  if(!node && path)
    node = get_kb_item("DB2/"+path+"/Node");
  if(!node && path_encode)
    node = get_kb_item("DB2/"+path_encode+"/Node");
  if(!path && port)
    path = get_kb_item("DB2/"+port+"/Path");
  if(path && !instance)
    instance = get_kb_item("DB2/"+path+"/Instances");
  else if(!path && !instance && port)
    instance = get_kb_item("DB2/"+port+"/Instances");
  if(path_encode && !instance)
    instance = get_kb_item("DB2/"+path_encode+"/Instances");
  if(empty_or_null(port))
    port = 0;

  if(platform_name)
    report += '\n  Platform                : ' + platform_name;
  if(installed_level)
    report += '\n  Installed level         : ' + installed_level;
  if(installed_version)
    report += '\n  Installed version       : ' + installed_version;
  if(path)
    report += '\n  Path                    : ' + path; # sanitization needed here
  if(instance)
    report += '\n  Instance                : ' + instance;
  if(product)
    report += '\n  Product                 : ' + product;
  if(node)
    report += '\n  Node                    : ' + node;
  if(special_installed)
    report += '\n  Installed Special Build : ' + special_installed;
  if(special_fix)
    report += '\n  Fixed Special Build     : ' + special_fix;
  if(fixed_level)
    report += '\n  Fixed level             : ' + fixed_level;
  if(fixed_version)
    report += '\n  Fixed version           : ' + fixed_version;
  if(info)
    report += '\n' + info;

  report += '\n';

  security_report_v4(port:port, severity:severity, extra:report);
}
