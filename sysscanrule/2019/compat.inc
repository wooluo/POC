#TRUSTED 89ffaea94e6a46c788e551c3e7ddd5c1e111148765666d1ab22a2cb4fde8fe186d4c2515dfe85ef17cf61bdd6e0dda48b441ca2aa32193b3ae8fd1230f3af507b80ab310640d68b9ecfb99eb0d2af2e96ab8fb00c2feacf645b1379e1beefbdb17755d2315dc34d090ec9fe1f5b35171bd35d56f22a7040c4e19cb9b87e263138abc53d1b3c6665621b70228c9948a9ffad315623bc37100620e75e0122e9457229bf9062dd9597d34bcf57015f095836eda5d76e979acfc6737727fc9a495fa84076545d48b869140ca062b487bdd351e687cf39fec7290691af19ab66b7129fb9eae2d0e116feb0dd5790e33a8c4c81dfde799c35f99a3098e16ffab01a90ab91817f9ff2f5d7e6f48f89ba428fbe06ca07fec5522b18203eb74c78430b98a45a65b9bd6bf49342b22645e47096c21befe1a74cd6d2dba97738016a5bfd758c96713ba0d059ac35ad7f9f663d3d04411f7c81079b5e25a5b43cdd70f018f1cea7f6d4a41fc9d5fb6d047a81413c61d2b4529ab272dea8af7e36a38dbec9edc81b0449ebd969430851ac5eb7fed3a61c27ce39123f590e70b61f18b0ad72b6774475fe365950f24db14d7d24d6d20a5efb92daab6a8a2c18ce01d7d28e673fde1596478c9d7772940ab25ba50500eaab13597ac4cad2f29bb0c0925c2632825ecd8fe1e8b8f93ed64b6a3dc023b55664be2f2212cf06231ba79e6fa7b39b0dc
#
# (C) WebRAY Network Security, Inc.
#
# Redistribution and use in source, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed by WebRAY Network Security
#
# Revision 1.21

include("compat_shared.inc");

#
# Backward compatibility functions
#



function cvss_vector_to_temporal_score(vector, base_score)
{
 local_var str;
 local_var Exploitability, RemediationLevel, ReportConfidence;
 local_var base;
 local_var score;

 str = vector;
 base_score = split(base_score, sep:'.');
 base = int(base_score[0]) * 1000 + int(base_score[1]) * 100;

 if ( "E:U/" >< str )
     Exploitability = 1176; # 0.85
 else if ( "E:POC/" >< str )
     Exploitability = 1111; # 0.9
 else if ( "E:F/" >< str )
     Exploitability = 1052; # 0.95
 else if ( "E:H/" >< str )
     Exploitability = 1000; # 1.00
 else #if ( "E:/" >< str || "E:ND/" >< str )
     Exploitability = 1000; # 1.00

 if ( "/RL:OF/" >< str )
     RemediationLevel = 1149; # 0.87
 else if ( "/RL:TF/" >< str )
     RemediationLevel = 1111; # 0.90
 else if ( "/RL:W/" >< str )
     RemediationLevel = 1052; # 0.95
 else if ( "/RL:U/" >< str )
     RemediationLevel = 1000; # 1.00
 else #if ( "/RL:/" >< str || "/RL:ND/" >< str )
     RemediationLevel = 1000; # 1.00

 if ( "/RC:UC" >< str )
     ReportConfidence = 1111; # 0.90
 else if ( "/RC:UR" >< str )
     ReportConfidence = 1052; # 0.95
 else if ( "/RC:C" >< str )
     ReportConfidence = 1000; # 1.00
 else #if ( "/RC:" >< str || "/RC:ND" >< str )
     ReportConfidence = 1000; # 1.00


 score = (base  * 1000)/Exploitability;
 score = (score * 1000)/RemediationLevel;
 score = (score * 1000)/ReportConfidence;
 if ( score % 100 >= 50) score += ( 100 - (score % 100) ); # Rounding
 if ( score / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( score % 100 >= 40) score += ( 100 - (score % 100) );
 }

 score = (score/10)*10;
 return ((score / 1000) + "." + (score % 1000)/100);
}

function cvss_vector_to_base_score()
{
 local_var str;
 local_var c,i,a;
 local_var AccessVector, AccessComplexity, Authentication;
 local_var q,z;
 local_var cvss_score;

 str = _FCT_ANON_ARGS[0];
 if ( "AV:L/" >< str )
   AccessVector = 2532;
 else if ( "AV:A/" >< str )
   AccessVector = 1548;
 else if ( "AV:N/" >< str)
   AccessVector = 1000;
 else
 {
   #display("Unknown CVSS access subvector (", str, ")!\n");
   return NULL;
 }

 if ( "AC:L/" >< str )
   AccessComplexity = 1408;
 else if ( "AC:M/" >< str )
   AccessComplexity = 1639;
 else if ( "AC:H/" >< str )
   AccessComplexity = 2857;
 else
 {
   #display("Unknown CVSS access complexity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "Au:N/" >< str )
   Authentication = 1420;
 else if ( "Au:S/" >< str )
   Authentication = 1786;
 else if ( "Au:M/" >< str )
   Authentication = 2222;
 else
 {
   #display("Unknown CVSS authentication subvector (", str, ")!\n");
   return NULL;
 }

 if ( "C:N/" >< str )
   c = 1000;
 else if ( "C:P/" >< str )
   c = 725;
 else if ( "C:C/" >< str )
   c = 340;
 else
 {
   #display("Unknown CVSS confidentiality subvector (", str, ")!\n");
   return NULL;
 }

 if ( "I:N/" >< str )
   i = 1000;
 else if ( "I:P/" >< str )
   i = 725;
 else if ( "I:C/" >< str )
   i = 340;
 else
 {
   #display("Unknown CVSS integrity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "/A:N" >< str )
   a = 1000;
 else if ( "/A:P" >< str )
   a = 725;
 else if ( "/A:C" >< str )
   a = 340;
 else
 {
   #display("Unknown CVSS availability subvector (", str, ")!\n");
   return NULL;
 }

 if ( c + i + a == 3000 )
   return "0.0";

 z = (c*1000)/( (1000*1000)/i);
 z = (z*1000)/( (1000*1000)/a);
 z = 1000 - z;
 z = (1000*1000)/z;
 z = (10410*1000)/z;
 z = (z*1000)/1666;

 q = ( AccessComplexity  * 1000 ) / (( 1000 * 1000 )/Authentication );
 q = ( q * 1000 ) / ( ( 1000 * 1000 ) / AccessVector );
 q = ( 1000 * 1000 ) / q;
 q = q * 20000;
 q = q / 2500;

 z = ( z + q ) - 1500;
 z = (z * 11760)/10000;
 if ( z % 100 >= 50) z += ( 100 - (z % 100) ); # Rounding
 if ( z / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( z % 100 >= 40) z += ( 100 - (z % 100) );
 }

 z = (z/10)*10;
 cvss_score = ((z / 1000) + "." + (z % 1000)/100);
 return cvss_score;
}

function script_set_cvss3_base_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  script_set_attribute(attribute:"cvss3_vector", value:vector);
}

function script_set_cvss3_temporal_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  script_set_attribute(attribute:"cvss3_temporal_vector", value:vector);
}

function script_set_cvss_base_vector()
{
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 script_set_attribute(attribute:"cvss_vector", value:vec);
}

function script_set_cvss_temporal_vector()
{
 local_var base_score;
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 script_set_attribute(attribute:"cvss_temporal_vector", value:vec);

}

function script_osvdb_id()
{
 var id = _FCT_ANON_ARGS[0];
}

function script_cwe_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"CWE", value: i);
}

function script_cvs_date()
{
  local_var	v;
  v = split(_FCT_ANON_ARGS[0], sep: ' ', keep: 0);
  if ( isnull(v) || isnull(v[1]) || v[1] !~ "^2[0-9]+/[0-9]+/[0-9]+$" ) return;
  script_set_attribute(attribute:"plugin_modification_date", value: v[1]);
}

