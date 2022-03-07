#TRUSTED 2af5903cef2c84ace9415266b0ce5849a45128646d6ded205ab768a017ed7fbd25350c53ab11136c9f84de22c40bad4a80032fc11f178bd954a9caf79d14287de55268bd2cf755d11b836fb7803576d6cf6a2d5c2709e75015e5fe14e317d8a5266e6d6c7235cd35ea9990c9bf96e4ad73914cf033b7a067e85fb03e60a5aeddf564d69274144f3de76b22cc9b85bba16c3b266d485b90c9ce0f915d581e48a283b1e00f9444ff698b9c0c2b544c6745ff473e623279b44e35badea5366d1b0266bf98d2c99f0f446b82c8ead19c5da19ecfb191318fb150c6c7ecc796a8de80908e4a5ea96aa1e8711884aee7caf1d6c0f0943b7adc6262ea5d8ecf516b72cd74c6dcdfe0e7be9b59f56301b7026eba8c3307958ebddee208fe1ec9d2731f4e812c7d6bf231c5d227216f91e464de24f9b8d635af61a8409277b874655203f38b451bb5898efe387e9b20603966d478d1501d64a18c1c71763aac4c1ab50fac9962680eb3271339ceff858e78469472bad1b0cf16759c168b75d6d1cebea75a3ba6538010f35cf8d04668c45cf6299217d79c0b6a8102d84a2a38268a6b4d0264ac3c19fdcc015308195b1752b066780f59f1fd06a17a6fe27d0966b57a75d1a49ff53e53f44e1e4a801f16ded41ef7678a512b1277ae5394d7a922b350491f8c81360edd45054097c20dbce48c6e49e11f582372c88e4596a852078456b8d9
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# x509_func.inc
#
# Revision: 1.38
#

include("misc_func_nlib.inc");
include("obj_nlib.inc");
include("ssl_funcs.inc");
include("kerberos_func.inc");
include("byte_func.inc");
include("ecc.inc");

namespace x509 {
  global_var distrusted_CA = NULL;
  global_var distrusted_CA_whitelist = NULL;
}

# OCSP
oid_name["1.3.6.1.5.5.7.48.1"] = "Online Certificate Status Protocol";
oid_name["1.3.6.1.5.5.7.48.2"] = "Certificate Authority Issuers";

# certificate RFC 2459
oid_name["1.3.6.1.5.5.7.3.1"] = "Web Server Authentication";
oid_name["1.3.6.1.5.5.7.3.2"] = "Web Client Authentication";
oid_name["1.3.6.1.5.5.7.3.3"] = "Code Signing";
oid_name["1.3.6.1.5.5.7.3.4"] = "E-Mail Protection";
oid_name["1.3.6.1.5.5.7.3.5"] = "IPSEC End System";
oid_name["1.3.6.1.5.5.7.3.6"] = "IPSEC Tunnel";
oid_name["1.3.6.1.5.5.7.3.7"] = "IPSEC User";
oid_name["1.3.6.1.5.5.7.3.8"] = "Time Stamping";
oid_name["1.3.6.1.5.5.7.3.9"] = "OCSP Responder";

# Netscape Policy
oid_name["2.16.840.1.113730.4.1"] = "Strong Crypto Export Approved";

# PKIX
oid_name["1.3.6.1.5.5.7.1.1"]     = "Authority Information Access";

# crypto
#
# nb: there a list of signing OIDs at <http://msdn.microsoft.com/en-us/library/aa379070%28v=vs.85%29.aspx>
oid_name["1.2.840.113549.1.1.1"]   = "RSA Encryption";
oid_name["1.2.840.113549.1.1.2"]   = "MD2 With RSA Encryption";
oid_name["1.2.840.113549.1.1.3"]   = "MD4 With RSA Encryption";
oid_name["1.2.840.113549.1.1.4"]   = "MD5 With RSA Encryption";
oid_name["1.2.840.113549.1.1.5"]   = "SHA-1 With RSA Encryption";
oid_name["1.2.840.113549.1.1.11"]  = "SHA-256 With RSA Encryption";
oid_name["1.2.840.113549.1.1.12"]  = "SHA-384 With RSA Encryption";
oid_name["1.2.840.113549.1.1.13"]  = "SHA-512 With RSA Encryption";
oid_name["1.2.840.113549.1.1.14"]  = "SHA-224 With RSA Encryption";
oid_name["1.2.840.10045.4.1"]      = "ECDSA With SHA-1";
oid_name["1.2.840.10045.4.3.2"]    = "ECDSA With SHA-256";
oid_name["1.2.840.10045.4.3.3"]    = "ECDSA With SHA-384";
oid_name["1.2.840.10045.4.3.4"]    = "ECDSA With SHA-512";
oid_name["1.3.14.3.2.15"]          = "SHA-0 With RSA Encryption";

oid_name["1.2.840.10040.4.3"]      = "SHA-1 With DSA Signature";
oid_name["1.3.14.3.2.29"]          = "SHA-1 With RSA Signature";
oid_name["1.2.840.113549.1.1.10"]  = "RSA-PSS Signature Scheme";

# Parameters for RSASSA-PSS signatures
oid_name["1.2.840.113549.1.1.8"]   = "MGF1";
oid_name["1.2.840.113549.2.4"] =     "MD4";
oid_name["1.2.840.113549.2.5"]     = "MD5";
oid_name["1.3.14.3.2.26"]          = "SHA-1";
oid_name["2.16.840.1.101.3.4.2.4"] = "SHA-224";
oid_name["2.16.840.1.101.3.4.2.1"] = "SHA-256";
oid_name["2.16.840.1.101.3.4.2.2"] = "SHA-384";
oid_name["2.16.840.1.101.3.4.2.3"] = "SHA-512";

alg_pointer["MGF1"] = @rsa_pss_mgf1;
alg_pointer["MD4"] = @MD4;
alg_pointer["MD5"] = @MD5;
alg_pointer["SHA-1"] = @SHA1;
alg_pointer["SHA-224"] = @SHA224;
alg_pointer["SHA-256"] = @SHA256;
alg_pointer["SHA-384"] = @SHA384;
alg_pointer["SHA-512"] = @SHA512;

# This is used for ECC public keys for both ECDSA signing and for ECDH.
oid_name["1.2.840.10045.2.1"]      = "EC Public Key";

# PKCS#9
oid_name["1.2.840.113549.1.9.1"]  = "Email Address";
oid_name["1.2.840.113549.1.9.2"]  = "Unstructured Name";
oid_name["1.2.840.113549.1.9.3"]  = "Content Type";
oid_name["1.2.840.113549.1.9.4"]  = "Message Digest";
oid_name["1.2.840.113549.1.9.5"]  = "Signing Time";
oid_name["1.2.840.113549.1.9.6"]  = "Counter Signature";
oid_name["1.2.840.113549.1.9.7"]  = "Challenge Password";
oid_name["1.2.840.113549.1.9.8"]  = "Unstructured Address";
oid_name["1.2.840.113549.1.9.9"]  = "Extended Certificate Attributes";
oid_name["1.2.840.113549.1.9.15"] = "S/MIME Capabilities";
oid_name["1.2.840.113549.1.9.20"] = "Friendly Name";
oid_name["1.2.840.113549.1.9.21"] = "Local Key ID";

# DC
oid_name["0.9.2342.19200300.100.1.1"] = "User Id";
oid_name["0.9.2342.19200300.100.1.3"] = "Email Address";
oid_name["0.9.2342.19200300.100.1.25"] = "Domain Component";

# Name data
oid_name["2.5.4.3"]   = "Common Name";
oid_name["2.5.4.4"]   = "Surname";
oid_name["2.5.4.6"]   = "Country";
oid_name["2.5.4.7"]   = "Locality";
oid_name["2.5.4.8"]   = "State/Province";
oid_name["2.5.4.9"]   = "Street";
oid_name["2.5.4.10"]  = "Organization";
oid_name["2.5.4.11"]  = "Organization Unit";
oid_name["2.5.4.12"]  = "Title";
oid_name["2.5.4.17"]  = "Postal Code";
oid_name["2.5.4.41"]  = "Name";
oid_name["2.5.4.42"]  = "Given Name";
oid_name["2.5.4.43"]  = "Initials";

# Certificate data
oid_name["2.5.29.5"]  = "Subject Directory Attributes";
oid_name["2.5.29.9"]  = "Subject Directory Attributes";
oid_name["2.5.29.14"] = "Subject Key Identifier";
oid_name["2.5.29.15"] = "Key Usage";
oid_name["2.5.29.16"] = "Key Usage Period";
oid_name["2.5.29.17"] = "Subject Alternative Name";
oid_name["2.5.29.18"] = "Issuer Alternative Name";
oid_name["2.5.29.19"] = "Basic Constraints";
oid_name["2.5.29.20"] = "CRL Number";
oid_name["2.5.29.21"] = "CRL Reason Code";
oid_name["2.5.29.23"] = "Hold Instruction Code";
oid_name["2.5.29.24"] = "Invalid Date";
oid_name["2.5.29.27"] = "Delta CRL Indicator";
oid_name["2.5.29.28"] = "Issuing Distribution Point";
oid_name["2.5.29.29"] = "Issuer";
oid_name["2.5.29.30"] = "Name Constraints";
oid_name["2.5.29.31"] = "CRL Distribution Points";
oid_name["2.5.29.32"] = "Policies";
oid_name["2.5.29.33"] = "Policy Mappings";
oid_name["2.5.29.34"] = "Policy Constraints";
oid_name["2.5.29.35"] = "Authority Key Identifier";
oid_name["2.5.29.36"] = "Policy Constraints";
oid_name["2.5.29.37"] = "Extended Key Usage";

# Netscape cert extensions
oid_name["2.16.840.1.113730.1.13"] = "Comment";

# PKIX Extended Key Usage Extension Uses
oid_name["1.3.6.1.4.1.311.10.3.1"] = "Certificate trust list signing";
oid_name["1.3.6.1.4.1.311.10.3.3"] = "Microsoft Server Gated Crypto (SGC)";
oid_name["1.3.6.1.4.1.311.10.3.4"] = "Microsoft Encrypted File System";
oid_name["2.16.840.1.113730.4.1"] = "Netscape SGC";

# PKIX
oid_name["1.3.6.1.5.5.7.2.1"] = "Certification Practice Statement";
oid_name["1.3.6.1.5.5.7.2.2"] = "User Notice";

OID_CPS_POINTER = "1.3.6.1.5.5.7.2.1";
OID_USER_NOTICE = "1.3.6.1.5.5.7.2.2";


global_var known_extensions;

EXTN_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
EXTN_KEY_USAGE = "2.5.29.15";
EXTN_EXTENDED_KEY_USAGE = "2.5.29.37";
EXTN_CRL_DIST_POINTS = "2.5.29.31";
EXTN_AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1";
EXTN_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
EXTN_SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";
EXTN_CERTIFICATE_COMMENT = "2.16.840.1.113730.1.13";
EXTN_CERTIFICATE_POLICIES = "2.5.29.32";
EXTN_BASIC_CONSTRAINTS = "2.5.29.19";

known_extensions[EXTN_KEY_USAGE] = TRUE;
known_extensions[EXTN_EXTENDED_KEY_USAGE] = TRUE;
known_extensions[EXTN_CRL_DIST_POINTS] = TRUE;
known_extensions[EXTN_AUTHORITY_INFORMATION_ACCESS] = TRUE;
known_extensions[EXTN_AUTHORITY_KEY_IDENTIFIER] = TRUE;
known_extensions[EXTN_SUBJECT_KEY_IDENTIFIER] = TRUE;
known_extensions[EXTN_SUBJECT_ALTERNATIVE_NAME] = TRUE;
known_extensions[EXTN_CERTIFICATE_COMMENT] = TRUE;
known_extensions[EXTN_CERTIFICATE_POLICIES] = TRUE;
known_extensions[EXTN_BASIC_CONSTRAINTS] = TRUE;

###
# These OIDs are used only by Microsoft.
# http://support.microsoft.com/kb/287547
###
EXTN_MS_ENROLL_CERTTYPE = "1.3.6.1.4.1.311.20.2";
EXTN_MS_CERTSRV_CA_VERSION = "1.3.6.1.4.1.311.21.1";

oid_name["1.3.6.1.4.1.311.20.2"] = "Certificate Template Name";
oid_name["1.3.6.1.4.1.311.21.1"] = "CA Version";

known_extensions[EXTN_MS_ENROLL_CERTTYPE] = TRUE;
known_extensions[EXTN_MS_CERTSRV_CA_VERSION] = TRUE;

###
# OIDs that indicate satisfaction of a validation requirement
###
CERTIFICATE_POLICY_EXTENDED_VALIDATION = "2.23.140.1.1";
CERTIFICATE_POLICY_DOMAIN_VAILDATION = "2.23.140.1.2.1";
CERTIFICATE_POLICY_ORG_VALIDATION = "2.23.140.1.2.2";
CERTIFICATE_POLICY_INDIVIDUAL_VALIDATION = "2.23.140.1.2.3";

function inv8 (x)
{
 local_var val, i;

 val = 0;

 for (i=0; i<8; i++)
   val = val + (((x >> (7-i)) & 1) << i);

 return val;
}


function load_CA_file(filename)
{
  var data = '';
  if (file_stat(filename) > 0) data += fread(filename);
  if ((strlen(data)) <= 0) return NULL;

  var inCert = FALSE;
  var n = 0;
  var line;
  var der;
  var raw = [];
  var ret = [];

  foreach line (split(data, keep:FALSE))
  {
    if (line =~ "^-+BEGIN CERTIFICATE-+$")
    {
      inCert = TRUE;
      der = NULL;
    }
    else if (line =~ "^-+END CERTIFICATE-+$")
    {
      raw[n] = base64_decode(str:der);
      ret[n] = parse_der_cert(cert:raw[n]);
      n++;
      der = NULL;
      inCert = FALSE;
    }
    else if (inCert) der += line;
  }

  inCert = FALSE;

  var r = [];
  r[0] = ret;
  r[1] = raw;

  return r;
}


function load_distrusted_CA()
{
  if(isnull(x509::distrusted_CA))
    x509::distrusted_CA = load_CA_file(filename:"distrusted_CA.inc");

  return x509::distrusted_CA;
}


function load_distrusted_CA_whitelist()
{
  if(isnull(x509::distrusted_CA_whitelist))
    x509::distrusted_CA_whitelist = load_CA_file(filename:"distrusted_CA_whitelist.inc");

  return x509::distrusted_CA_whitelist;
}


function is_CA_distrusted(chain, return_cert)
{
  var cert, affected, bad_ca;
  var affected_ca, whitelisted_ca;

  if ( isnull(x509::distrusted_CA) )
    load_distrusted_CA();
  if ( isnull(x509::distrusted_CA_whitelist) )
    load_distrusted_CA_whitelist();

  chain = sort_cert_chain(chain);

  foreach cert (chain)
  {
    foreach bad_ca (x509::distrusted_CA[0])
    {
      if( is_signed_by(cert, bad_ca) )
      {
        affected = TRUE;
        affected_ca = bad_ca;
        break;
      }
    }
  }
  foreach cert (chain)
  {
    foreach whitelisted_ca (x509::distrusted_CA_whitelist[0])
    {
      if( is_signed_by(cert, whitelisted_ca) )
      {
        affected = FALSE;
        affected_ca = NULL;
        break;
      }
    }
  }


  if(return_cert)
    return affected_ca;

  return affected;
}


# Also compatible with DSA (non-EC) signatureValue
function parse_ecdsa_signaturevalue(sv)
{
  local_var seq, r, s, diff;

  seq = der_parse_sequence(seq:sv, list:TRUE);
  r = der_parse_data(tag:0x02, data:seq[1]);
  s = der_parse_data(tag:0x02, data:seq[2]);

  if (ord(r[0]) == 0)
    r = substr(r, 1);

  if (ord(s[0]) == 0)
    s = substr(s, 1);


  if (isnull(r) || strlen(r) <= 1)
    return NULL;

  if (isnull(s) || strlen(s) <= 1)
    return NULL;

  diff = strlen(r) - strlen(s);
  if(diff < 0)
    diff *= -1;

  # When null bytes are removed from the beginning the lengths may be off by one
  if(diff > 1 )
    return NULL;

  return { "r": r, "s": s };

}

# A SignatureValue and SubjectPublicKeyInfo can both say "this is not
# only an RSA key - this is an RSA key that should only be used with
# RSASSA-PSS signatures, and these are the parameters to use for those
# signatures".
# In effect, the signing key (on the CA certificate, for example) can
# be listed as an RSASSA-PSS key and that all signatures must use
# SHA256, for example.
function parse_rsapss_parameters(param)
{
  local_var ret, pos, params, tmp, i;

  # Set initially to defaults, and default = TRUE. If explicitly set
  # in the params field, we set default = FALSE and replace the value.
  # In the same order as they are in the ASN.1 SEQUENCE in the RFC.
  params = [
    { "value": "1.3.14.3.2.26", "default": TRUE }, # hashAlgorithm, defaults to SHA1
    { "value": "1.2.840.113549.1.1.8", "hash": "1.3.14.3.2.26",  "default": TRUE }, # maskGenAlgorithm, defaults to MGF1 with SHA1 as a parameter
    { "value": 20, "default": TRUE }, # saltLength, defaults to 20
    { "value": 1, "default": TRUE }, # trailerField, defaults to 1
  ];

  ret = der_parse_sequence(seq:param, list:TRUE);
  if (isnull(ret))
    return NULL;

  # Walk list of parameters
  for (i = 1; i < ret[0] + 1; ++i)
  {
    tmp = der_decode(data:ret[i]);
    # Make sure this is a context-specific tag for a constructed type, that is
    # that the first three bits are "101". If so, the remaining 5 bits are an
    # integer that basically names the element; because these elements are all
    # optional, they each have a name (just an integer) attached to them to
    # say which is which.
    if (tmp[0] & 0xE0 != 0xA0)
      return NULL;

    # Pull out the integer value encoded in this context-specific tag. This
    # tells us what element this is that we're dealing with.
    pos = tmp[0] & 0x1F;
    # 0-3 are the only valid parameter "names" for RSA-PSS
    if (pos > 3 || pos < 0)
      return NULL;

    # We got a parameter, so blank out the default we previously set
    params[pos].default = FALSE;
    params[pos].value = NULL;
    # Only for MGF1
    if (params[pos].hash)
      params[pos].hash = NULL;

    # hashAlgorithm - an AlgorithmIdentifier
    if (pos == 0)
    {
      tmp = der_parse_sequence(seq:tmp[1], list:TRUE);
      params[pos].value = der_parse_oid(oid:tmp[1]);
      # We won't check the parameters field for this AlgorithmIdentifier
      # It can be NULL or absent and it doesn't matter to us either way
      if (isnull(params[pos].value))
        return NULL;
    }
    # maskGenAlgorithm - an AlgorithmIdentifier with another one nested in its parameters
    else if (pos == 1)
    {
      tmp = der_parse_sequence(seq:tmp[1], list:TRUE);
      params[pos].value = der_parse_oid(oid:tmp[1]);
      tmp = der_parse_sequence(seq:tmp[2], list:TRUE);
      params[pos].hash = der_parse_oid(oid:tmp[1]);
      # OpenSSL thinks that an absent param for MGF1 is illegal, so
      # we will treat it the same way.
      if (isnull(params[pos].value) || isnull(params[pos].hash))
        return NULL;
    }
    # saltLen - an integer
    else if (pos == 2)
    {
      params[pos].value = der_parse_int(i:tmp[1]);
      if (isnull(params[pos].value))
        return NULL;
    }
    # trailerField - an integer
    else if (pos == 3)
    {
      params[pos].value = der_parse_int(i:tmp[1]);
      if (isnull(params[pos].value))
        return NULL;
    }
  }

  return params;
}

# When RSASSA-PSS parameters exist on a public key, the parameters
# on any signatures generated by that key must be the same *except*
# for the "saltlen" which may be longer.
# Returns TRUE if the parameters are "allowed", and FALSE otherwise
# This compares the returns from parse_rsapss_params().
function cmp_rsapss_parameters(ca, leaf)
{
  # What we are doing here is just checking each of the four parameters in turn for equality
  # We could loop over them, but some of them require special handling.

  # If hash is not the same
  if (ca[0].value != leaf[0].value)
    return FALSE;

  # The mask function.
  # MGF is parameterized with a hash, so make sure that's the same too.
  if (ca[1].hash != leaf[1].hash || ca[1].value != leaf[1].value)
    return FALSE;

  # Saltlen. The leaf's is allowed to be longer, or equal to, the CA's.
  # Shorter is not allowed.
  if (ca[2].value > leaf[2].value)
    return FALSE;

  # Trailer field
  if (ca[3].value != leaf[3].value)
    return FALSE;

  return TRUE;
}

function parse_publickey_info(pki)
{
 local_var pos, ret, ai_algo, ai_param, ai_len, tmp, seq, pk, e, n, pubkey, curve_info, x, y;
 local_var raw_key;
 pos = 0;

 ret = der_decode(data:pki, pos:pos);
 if (isnull(ret) || ret[0] != 0x30) return NULL;
 pos = ret[2];

 # AlgorithmIdentifier
 ret = der_parse_list(list:ret[1]);
 if (isnull(ret)) return NULL;
 ai_len = ret[0];
 ai_algo = der_parse_oid(oid:ret[1]);
 # Used by EC public keys this is most commonly an OID for a named curve
 # For RSA keys this is always NULL (RFC3279 sections 2.3.1 and 2.3.5)
 # For RSA-PSS keys this will be entirely absent, or a SEQUENCE with
 # 4 paramters, all optional (so an empty sequence is legal). NULL is
 # not legal here.
 ai_param = ret[2];

 # 0x03 is the tag for ASN.1 BIT STRING
 ret = der_decode(data:pki, pos:pos);
 if (isnull(ret) || ret[0] != 0x03) return NULL;
 raw_key = ret[1];
 # RSA
 if ("1.2.840.113549.1.1.1" >< ai_algo || ai_algo == "1.3.14.3.2.15")
 {
   # RSA-PSS: has parameters, and might actually have no ai_param at
   # all if no restrictions on this key are desired.
   if (ai_algo == "1.2.840.113549.1.1.10")
   {
     # RSA-PSS keys can have no parameter (totally absent) in which
     # case their use is unrestricted. This is not ASN.1 NULL, it is
     # complete absense. The ASN.1 SEQUENCE is just one element instead
     # of two. Contrast this with regular RSA keys that have two elements,
     # but the second element is ASN.1 NULL.
     if (ai_len < 2 || isnull(ai_param))
       tmp[2] = FALSE;
     else
       tmp[2] = parse_rsapss_parameters(param:ai_param);
   }

   # ai_param should be an ASN.1 NULL here if regular RSA key.
   # We could check it, but maybe it's not always, so we'll leave it.
   seq = der_parse_sequence (seq:substr(ret[1], 1, strlen(ret[1])-1),list:TRUE);
   if (isnull(seq) || seq[0] != 2)
     return NULL;

   n = der_parse_data(tag:0x02, data:seq[1]);
   e = der_parse_data(tag:0x02, data:seq[2]);
   tmp[1] = make_list(n,e);
 }
 # EC Public Key (unspecified whether for ECDH or ECDSA)
 else if (ai_algo == "1.2.840.10045.2.1")
 {
   # EC public keys always have an ai_param and it's the name of the curve
  if (ai_len < 2 || isnull(ai_param))
    return NULL;

   # The OID of the named curve
   tmp[2] = der_parse_oid(oid:ai_param);
   if (isnull(tmp[2]))
     return NULL;

   pubkey = substr(ret[1], 1);
   # We only support uncompressed (0x04) ECPoints.
   # All implementations MUST support this format.
   # See X9.62-1998 section 4.3.6 for the various encodings.
   if (ord(pubkey[0]) != 0x04)
     return NULL;

   # The format is "0x04 || X || Y".
   # X and Y are both the same length so this must be odd length.
   if (strlen(pubkey) % 2 != 1 || strlen(pubkey) < 3)
     return NULL;

   x = substr(pubkey, 1, (strlen(pubkey) - 1) / 2);
   y = substr(pubkey, 1 + (strlen(pubkey) - 1) / 2);
   tmp[1] = make_list(x,y);
 }
 # Unsupported algorithm
 else
 {
   return NULL;
 }

 tmp[0] = ai_algo;
 tmp[3] = raw_key;
 # [0] is the algorithm OID
 # [1] is the key data, as a list (n,e for RSA, x,y for EC)
 # [2] is only set if this is an EC key or an RSAPSS key
 # [3] is the raw key blob, needed for building the OCSP IssuerKeyHash
 #   * for EC, it is the OID of the named curve
 #   * for RSAPSS, it is the parameters of the key or FALSE if none
 return tmp;
}


function parse_attribute_type_and_value(a)
{
 local_var seq, list, oid, ret, at;

 seq = der_parse_data(tag:0x31, data:a);
 if (isnull(seq)) return NULL;

 list = der_parse_sequence(seq:seq, list:TRUE);
 if (isnull(list) || list[0] != 2) return NULL;

 oid = der_parse_oid(oid:list[1]);
 if (isnull(oid)) return NULL;

 ret = der_decode(data:list[2]);
 if (isnull(ret)) return NULL;

 # uTF8String && PrintableString && T61String && IA5String && BMPString
 if (ret[0] != 12 && ret[0] != 19 && ret[0] != 20 && ret[0] != 22 && ret[0] != 30)
 {
  #display("AT: unsupported string encoding: ", ret[0], " !\n");
  return NULL;
 }

 # Perform an naive translation of a UTF-16 string by removing all NUL
 # bytes. This is the best we can do until we have full Unicode
 # support. Foreign languages will be mangled by this, but at least
 # they'll parse.
 if (ret[0] == 30)
   ret[1] = str_replace(find:raw_string(0), replace:"", string:ret[1]);

 at = NULL;
 at[0] = oid;
 at[1] = ret[1];

 return at;
}


function parse_rdn_sequence(seq)
{
 local_var list, rdns, num, i, ret;

 list = der_parse_list(list:seq);
 if (isnull(list)) return NULL;

 rdns = NULL;

 num = list[0];
 for (i=0; i<num; i++)
 {
  ret = parse_attribute_type_and_value(a:list[i+1]);
  if (isnull(ret)) return NULL;

  rdns[i] = ret;
 }

 return rdns;
}


global_var mons;

mons[1]  = "Jan";
mons[2]  = "Feb";
mons[3]  = "Mar";
mons[4]  = "Apr";
mons[5]  = "May";
mons[6]  = "Jun";
mons[7]  = "Jul";
mons[8]  = "Aug";
mons[9]  = "Sep";
mons[10] = "Oct";
mons[11] = "Nov";
mons[12] = "Dec";


function int2()
{
 local_var i, temp;
 i = _FCT_ANON_ARGS[0];

 temp = int(i);
 if (i < 10)
   temp = "0" + temp;

 return temp;
}


function convert_all_time(year, time)
{
 local_var i, temp;

 temp = NULL;

 for (i=0; i<6; i++)
   temp[i] = int(substr(time, i*2, (i+1)*2-1));

 return mons[temp[0]] + " " +
        int2(temp[1]) + " " +
        int2(temp[2]) + ":" + int2(temp[3]) + ":" + int2(temp[4]) + " " +
        year + " GMT";
}


# rfc3280: UTCTime -> YYMMDDHHMMSSZ GMT
function convert_utc_time(time)
{
 local_var year;

 if (strlen(time) != 13) return time;

 year = int(substr(time, 0, 1));
 if (year >= 50)
   year = 1900+year;
 else
   year = 2000+year;

 return convert_all_time(year:year, time:substr(time, 2, 11));
}


# rfc3280: GeneralizedTime -> YYYYMMDDHHMMSSZ GMT
function convert_generalized_time(time)
{
 local_var year;

 if (strlen(time) != 15) return time;

 year = int(substr(time, 0, 3));

 return convert_all_time(year:year, time:substr(time, 4, 13));
}


function parse_time(time)
{
 local_var ret;

 ret = der_decode(data:time);
 if (isnull(ret) || (ret[0] != 0x17 && ret[0] != 0x18)) return NULL;

 # UTCTime
 if (ret[0] == 0x17)
   return convert_utc_time(time:ret[1]);

 # GeneralizedTime
 if (ret[0] == 0x18)
   return convert_generalized_time(time:ret[1]);

 return NULL;
}


function parse_algorithm_identifier(ai)
{
 local_var ret;

 ret = der_parse_sequence(seq:ai, list:TRUE);
 if (isnull(ret) || ret[0] < 1) return NULL;

 return der_parse_oid(oid:ret[1]);
}


function parse_flags(data)
{
 local_var bits, val, i, len;

 bits = der_parse_data(tag:0x03, data:data);
 if (isnull(bits)) return NULL;

 val = 0;
 len = strlen(bits);
 
 for (i=0; i<len; i++)
   val = (val << 8) + inv8(x:ord(bits[i]));

 return val;
}


# return a dword (flags)
function parse_key_usage(data)
{
 return parse_flags(data:data);
}


function parse_extended_key_usage(data)
{ 
 local_var seq, tmp, i, oid;

 seq = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(seq) || seq[0] == 0) return NULL;

 tmp = NULL;

 for (i=0; i<seq[0]; i++)
 {
  oid = der_parse_oid(oid:seq[i+1]);
  if (isnull(oid)) return NULL;

  tmp[i] = oid;
 }

 return tmp;
}


function parse_basic_constraints(data)
{
  local_var is_ca, pathlen, seq, tmp;

  seq = der_parse_sequence(seq:data, list:TRUE);
  if (isnull(seq) || seq[0] == 0) return NULL;

  tmp = make_array();

  if (seq[0] >= 1)
  {
    is_ca = der_parse_bool(bool:seq[1]);
    if (!isnull(is_ca))
      tmp["ca"] = is_ca;
  }

  if (seq[0] >= 2)
  {
    pathlen = der_parse_int(i:seq[2]);
    if (!isnull(pathlen))
      tmp["pathlen"] = pathlen;
  }

  return tmp;
}

function parse_ip_address(address)
{
  if(strlen(address) == 4)
  {
    return '' + ord(address[0]) +
           '.' + ord(address[1]) +
           '.' + ord(address[2]) +
           '.' + ord(address[3]);
  }
  else if(strlen(address) == 16)
  {
    var i;
    var result = '';

    for(i = 0; i < 16; i ++)
    {
      result += hexstr(address[i]);
      if(i % 2 == 1 && i < 15) result += ":";
    }

    #Resolve IPv6 addresses directly to normalize their form
    result = resolv(name:result, ipv6:TRUE);
    return result[0];
  }
  else return NULL;
}


function parse_general_name(name)
{
 local_var ret, tmp, seq;

 ret = der_decode(data:name);
 if (isnull(ret)) return NULL;

 if (! (ret[0] & 0x80) ) return NULL;

 ret[0] = ret[0] & 0x1F;

 tmp = NULL;

 if (ret[0] == 0)
   tmp["otherName"] = ret[1];

 else if (ret[0] == 1)
   tmp["rfc822Name"] = ret[1];

 else if (ret[0] == 2)
   tmp["dNSName"] = ret[1];

 else if (ret[0] == 4)
 {
  seq = der_parse_data(tag:0x30, data:ret[1]);
  if (isnull(seq)) return NULL;

  tmp["directoryName"] = parse_rdn_sequence(seq:seq);
 }

 else if (ret[0] == 6)
   tmp["uniformResourceIdentifier"] = ret[1];

 else if (ret[0] == 7)
   tmp["iPAddress"] = parse_ip_address(address:ret[1]);

 else if (ret[0] == 8)
   tmp["registeredID"] = der_decode_oid(oid:ret[1]);

 else
 {
  #display("GN: Unsupported general name!\n");
  return NULL;
 }

 return tmp;
}


function parse_general_names(names)
{
 local_var seq, tmp, i, name;

 seq = der_parse_list(list:names);
 if (isnull(seq) || seq[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<seq[0]; i++)
 {
  name = parse_general_name(name:seq[i+1]);
  if (isnull(name)) return NULL;

  tmp[i] = name;
 }

 return tmp;
}


function parse_distribution_point(dp)
{
 local_var seq, ret, tmp, reasons, issuer;

 seq = der_parse_sequence(seq:dp, num:3, list:FALSE);
 if (isnull(seq)) return NULL;

 dp = reasons = issuer = NULL;

 if (!isnull(seq[0]))
 {
  ret = der_decode(data:seq[0]);
  if (isnull(ret) && ret[0] != 0xa0 && ret[0] != 0xa1) return NULL; 

  if (ret[0] == 0xa0)
    dp = parse_general_names(names:ret[1]);

#  if (ret[0] == 0xa1)
#    dp = parse_relative_distinguished_name(name:ret[1]);
 }

 if (!isnull(seq[1]))
   reasons = parse_flags(data:seq[1]);

 if (!isnull(seq[2]))
   issuer = parse_general_names(names:seq[2]);

 tmp = NULL;
 tmp["distributionPoint"] = dp;
 tmp["reasons"] = reasons;
 tmp["cRLIssuer"] = issuer;

 return tmp;
}


function parse_crl_distribution_points(data)
{
 local_var ret, tmp, i, dp;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<ret[0]; i++)
 {
  dp = parse_distribution_point(dp:ret[i+1]);
  if (isnull(dp)) return NULL;

  tmp[i] = dp;
 }

 return tmp;
}


function parse_access_description(ad)
{
 local_var ret, tmp, method, location;

 ret = der_parse_sequence(seq:ad, list:TRUE);
 if (isnull(ret) || ret[0] != 2) return NULL;
 
 method = der_parse_oid(oid:ret[1]);
 if (isnull(method)) return NULL;

 location = parse_general_name(name:ret[2]);
 if (isnull(location)) return NULL;

 tmp = NULL;
 tmp["accessMethod"] = method;
 tmp["accessLocation"] = location;

 return tmp;
}


function parse_authority_information_access(data)
{
 local_var ret, tmp, i, ad;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<ret[0]; i++)
 {
  ad = parse_access_description(ad:ret[i+1]);
  if (isnull(ad)) return NULL;

  tmp[i] = ad;
 }

 return tmp;
}


function parse_authority_key_identifier(data)
{
 local_var ret, ki, issuer, serial, tmp, i;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret)) return NULL;

 ki = issuer = serial = NULL;

 i = 1;
 if (ret[0] >= i)
 {
   ki = der_parse_data(tag:0x80, data:ret[i]);
   if(!isnull(ki)) i++;
 }

 if (ret[0] >= i)
 {
   tmp = der_decode(data:ret[i]);
   if(tmp[1]) issuer = parse_general_names(names:tmp[1]);
   if(!isnull(issuer)) i++;
 }

 if (ret[0] >= i)
 {
   serial = der_parse_data(tag:0x82, data:ret[i]);
 }

 tmp = NULL;
 tmp["keyIdentifier"] = ki;
 tmp["authorityCertIssuer"] = issuer;
 tmp["authorityCertSerialNumber"] = serial;

 return tmp;
}


function parse_subject_key_identifier(data)
{
 return der_parse_octet_string(string:data);
}


function parse_subject_alternative_name(data)
{
 local_var ret;

 ret = der_parse_data(tag:0x30, data:data);
 if (isnull(ret)) return NULL;

 return parse_general_names(names:ret);
}


function parse_certificate_comment(data)
{
 local_var ret;

 # IA5String
 ret = der_parse_data(tag:0x16, data:data);
 if (isnull(ret)) return NULL;

 return ret;
}


function parse_policy_qualifier_information(data)
{
 local_var ret, tmp, oid, qualifier;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] != 2) return NULL;

 oid = der_parse_oid(oid:ret[1]); 
 if (isnull(oid) || (oid != OID_CPS_POINTER && oid != OID_USER_NOTICE))
   return NULL;

 if (oid == OID_CPS_POINTER)
 {
  qualifier = der_parse_data(tag:22, data:ret[2]);
  if (isnull(qualifier)) return NULL;
 }
 else if (oid == OID_USER_NOTICE)
 {
  #display("PI: Unsupported user notice!\n");
  return NULL;
 }

 tmp = NULL;
 tmp["policyQualifierId"] = oid;
 tmp["qualifier"] = qualifier;

 return tmp;
}


function parse_policy_information(data)
{
 local_var ret, tmp, oid, qualifiers, i, seq;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 oid = der_parse_oid(oid:ret[1]); 
 if (isnull(oid)) return NULL;

 qualifiers = NULL;
 if (ret[0] == 2)
 {
  seq = der_parse_sequence(seq:ret[2], list:TRUE);
  if (isnull(seq)) return NULL;

  qualifiers = NULL;
  for (i=0; i<seq[0]; i++)
    qualifiers[i] = parse_policy_qualifier_information(data:seq[i+1]);
 }

 tmp = NULL;
 tmp["policyIdentifier"] = oid;
 tmp["policyQualifiers"] = qualifiers;

 return tmp;
}


function parse_certificate_policies(data)
{
 local_var ret, tmp, i, pi;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<ret[0]; i++)
 {
  pi = parse_policy_information(data:ret[i+1]);
  if (isnull(pi)) return NULL;

  tmp[i] = pi;
 }

 return tmp;
}


function parse_ms_enroll_certtype(data)
{
  local_var ret;

  ret = der_decode(data:data);
  if (isnull(ret))
    return NULL;

  # uTF8String && PrintableString && T61String && IA5String && BMPString
  if (ret[0] != 12 && ret[0] != 19 && ret[0] != 20 && ret[0] != 22 && ret[0] != 30)
    return NULL;

  # Perform a naive translation of a UTF-16 string by removing all NUL
  # bytes. This is the best we can do until we have full Unicode
  # support. Foreign languages will be mangled by this, but at least
  # they'll parse.
  if (ret[0] == 30)
    ret[1] = str_replace(find:raw_string(0), replace:"", string:ret[1]);

  return make_array("type", ret[1]);
}


function parse_ms_certsrv_ca_ver(data)
{
  local_var idx_crt, idx_key, num;

  # The extension data is a DWORD value (encoded as X509_INTEGER in
  # the extension); the low 16 bits are the certificate index, and the
  # high 16 bits are the key index.
  #
  # http://msdn.microsoft.com/en-us/library/windows/desktop/aa376550%28v=vs.85%29.aspx
  num = der_parse_int(i:data);
  if (isnull(num))
    return NULL;

  idx_crt = num & 0x0000FFFF;
  idx_key = num >>> 16;

  return make_array(
    "cert", idx_crt,
    "key", idx_key
  );
}


function parse_extension(extension)
{
 local_var ret, list, i, tmp, os, critical, oid;

 ret = der_parse_sequence(seq:extension, list:TRUE);
 if (isnull(ret) || ret[0] < 2) return NULL;

 oid = der_parse_oid(oid:ret[1]);
 if (isnull(oid)) return NULL;

 if (ret[0] == 2)
 {
  os = ret[2];
  critical = FALSE;
 }
 else
 {
  critical = der_parse_data(tag:0x01, data:ret[2]);
  if (ord(critical[0]) == 0)
    critical = FALSE;
  else
    critical = TRUE;

  os = ret[3];
 }

 os = der_parse_octet_string(string:os);
 if (isnull(os)) return NULL;

 if (oid == EXTN_KEY_USAGE)
   os = parse_key_usage(data:os);

 if (oid == EXTN_EXTENDED_KEY_USAGE)
   os = parse_extended_key_usage(data:os);

 if (oid == EXTN_CRL_DIST_POINTS)
   os = parse_crl_distribution_points(data:os);

 if (oid == EXTN_AUTHORITY_INFORMATION_ACCESS)
   os = parse_authority_information_access(data:os);

 if (oid == EXTN_AUTHORITY_KEY_IDENTIFIER)
   os = parse_authority_key_identifier(data:os);

 if (oid == EXTN_SUBJECT_KEY_IDENTIFIER)
   os = parse_subject_key_identifier(data:os);

 if (oid == EXTN_SUBJECT_ALTERNATIVE_NAME)
   os = parse_subject_alternative_name(data:os);

 if (oid == EXTN_CERTIFICATE_COMMENT)
   os = parse_certificate_comment(data:os);

 if (oid == EXTN_CERTIFICATE_POLICIES)
   os = parse_certificate_policies(data:os);

 if (oid == EXTN_BASIC_CONSTRAINTS)
   os = parse_basic_constraints(data:os);

 if (oid == EXTN_MS_ENROLL_CERTTYPE)
   os = parse_ms_enroll_certtype(data:os);

 if (oid == EXTN_MS_CERTSRV_CA_VERSION)
   os = parse_ms_certsrv_ca_ver(data:os);

 extension = NULL;
 extension["extnID"] = oid;
 extension["critical"] = critical;
 extension["extnValue"] = os;

 return extension;
}


function parse_extensions(extensions)
{
 local_var ret, list, i, tmp;

 ret = der_parse_sequence(seq:extensions, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 list = NULL;

 for (i=0; i<ret[0]; i++)
 {
  tmp = parse_extension(extension:ret[i+1]);
  if (isnull(tmp)) return NULL;

  if ( isnull(list) ) list = make_list();
  list[i] = tmp;
 }

 return list;
}


function parse_tbs_certificate(cert, include_blobs)
{
 local_var seq, tbs, pos, i;
 local_var tlist, tmp, ret;
 local_var serial, sig, issuer, extensions;
 local_var validity, subject, key, version;
 local_var nb, na, list;
 local_var raw_key;

 seq = der_decode (data:cert);
 if (isnull(seq) || (seq[0] != 0x30))
   return NULL;

 tlist = tmp = NULL;
 pos = i = 0;

 while (pos < strlen(seq[1]))
 {
  ret = der_decode (data:seq[1],pos:pos);
  if (isnull(ret))
    return NULL;

  if (ret[0] >= 0xa0)
    tlist[ret[0] - 0xa0] = ret[1];
  else
    tmp[i++] = ret;

  pos = ret[2];
 }

 # serialNumber
 ret = tmp[0];
 if (ret[0] != 0x02) return NULL;
 serial = ret[1];

 # signature
 ret = tmp[1];
 if (ret[0] != 0x30) return NULL;

 list = der_parse_list(list:ret[1]);
 if (isnull(list) || list[0] == 0) return NULL;

 sig = der_parse_oid(oid:list[1]);

 # issuer
 ret = tmp[2];
 if (ret[0] != 0x30) return NULL;
 var raw_issuer = der_encode(tag:0x30, data:ret[1]);
 issuer = parse_rdn_sequence(seq:ret[1]);
 if (isnull(issuer)) return NULL;

 # validity
 ret = tmp[3];
 if (ret[0] != 0x30) return NULL;

 list = der_parse_list(list:ret[1]);
 if (isnull(list) || list[0] != 2) return NULL;

 nb = parse_time(time:list[1]);
 if (isnull(nb)) return NULL;

 na = parse_time(time:list[2]);
 if (isnull(na)) return NULL;

 validity = NULL;
 validity["notBefore"] = nb;
 validity["notAfter"] = na;

 # subject
 ret = tmp[4];
 if (ret[0] != 0x30) return NULL;
 subject = parse_rdn_sequence(seq:ret[1]);

 # subjectPublicKeyInfo
 ret = tmp[5];
 if (ret[0] != 0x30) return NULL;
 var key_info_arr = parse_publickey_info(pki:ret[1]);
 key = [key_info_arr[0], key_info_arr[1]];
 if (!isnull(key_info_arr[2]))
   key[2] = key_info_arr[2];

 # version
 version = tlist[0];
 if (isnull(version))
   version = 0;
 else
   version = der_parse_int(i:version);

 # extensions
 extensions = tlist[3];
 if ((version == 2 || version == 3) && !isnull(extensions))
   extensions = parse_extensions(extensions:extensions);

 tbs = NULL;
 tbs["version"] = version;
 tbs["serialNumber"] = serial;
 tbs["signature"] = sig;
 tbs["issuer"] = issuer;
 if (include_blobs)
   tbs['rawIssuer'] = raw_issuer;
 tbs["validity"] = validity;
 tbs["subject"] = subject;
 tbs["subjectPublicKeyInfo"] = key;
 if (include_blobs)
   tbs["rawSubjectPublicKeyInfo"] = key_info_arr[3];
 tbs["extensions"] = extensions;

 return tbs;
}


function parse_der_cert(cert, customCA, include_blobs)
{
 local_var seq, tbs, ai, sig, ap;

 if(isnull(customCA))
   customCA = FALSE;

 seq = der_parse_sequence (seq:cert,list:TRUE);
 if (isnull(seq) || seq[0] != 3)
   return NULL;

 tbs = parse_tbs_certificate(cert:seq[1], include_blobs:include_blobs);
 if (isnull(tbs)) return NULL;

 ai = parse_algorithm_identifier(ai:seq[2]);
 if (isnull(ai)) return NULL;

 # RSA-PSS
 if (ai == "1.2.840.113549.1.1.10")
 {
   ap = der_parse_sequence(seq:seq[2], list:TRUE);
   # If parameters are absent entirely on the signature, we set to FALSE,
   # to be consistent with what we do for parameters on keys.
   # Parameters are allowed to be absent for keys but not signatures,
   # so this should almost be a parse error, but we could expose this
   # to customers if we ever see it.
   if (isnull(ap) || ap[0] < 2)
     ap = FALSE;
   else
   {
     ap = parse_rsapss_parameters(param:ap[2]);
   }
 }
 else
 {
   # AlgorithmIdentifier parameters
   ap = NULL;
 }


 sig = der_parse_data(tag:0x03, data:seq[3]);
 if (isnull(sig)) return NULL;

 cert = NULL;
 cert["tbsCertificate"] = tbs;
 cert["signatureAlgorithm"] = ai;
 # Just for RSA-PSS at the moment
 cert["signatureAlgorithmParameters"] = ap;
 cert["signatureValue"] = sig;
 cert["customCA"] = customCA;
 return cert;
}


function hex_buf(buf, space)
{
 local_var len, tmp, i;

 tmp = NULL;

 len = strlen(buf);
 for (i=0;i<len;i++)
 {
  if ( (i != 0) && (i % 20) == 0 )
    tmp += '\n' + crap(data:" ", length:space);

  tmp += toupper(hexstr(buf[i])) + " ";
 }

 return tmp;
}


function add_string(name, data)
{
 return name + ": " + data + '\n';
}


function add_string_nl(name, data)
{
 return add_string(name:name, data:data) + '\n';
}


function add_hex_string(name, data)
{
 local_var len;

 len = strlen(name) + 2;

 return name + ": " + hex_buf(buf:data, space:len) + '\n';
}


function add_hex_string_nl(name, data)
{
 return add_hex_string(name:name, data:data) + '\n';
}


function add_rdn_seq(seq)
{
 local_var tmp, name, type;

 tmp = NULL;
 if (isnull(seq)) return "";

 foreach name (seq)
 {
  type = name[0];

  if (!isnull(oid_name[type]))
    type = oid_name[type];

  tmp += add_string(name:type, data:name[1]);
 }

 return tmp;
}


function add_rdn_seq_nl(seq)
{
 return add_rdn_seq(seq:seq) + '\n';
}


function is_known_extension(id)
{
 if (!isnull(known_extensions[id]) && known_extensions[id] == TRUE)
   return TRUE;

 return FALSE;
}


function add_extension_data(extension)
{
 if (extension["extnID"] == EXTN_KEY_USAGE)
   return add_key_usage(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_EXTENDED_KEY_USAGE)
   return add_extended_key_usage(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_CRL_DIST_POINTS)
   return add_crl_distribution_points(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_AUTHORITY_INFORMATION_ACCESS)
   return add_authority_information_access(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_AUTHORITY_KEY_IDENTIFIER)
   return add_authority_key_identifier(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_SUBJECT_KEY_IDENTIFIER)
   return add_subject_key_identifier(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_SUBJECT_ALTERNATIVE_NAME)
   return add_subject_alternative_name(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_CERTIFICATE_COMMENT)
   return add_string_nl(name:"Comment", data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_CERTIFICATE_POLICIES)
   return add_certificate_policies(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_BASIC_CONSTRAINTS)
   return add_basic_constraints(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_MS_ENROLL_CERTTYPE)
   return add_ms_enroll_certtype(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_MS_CERTSRV_CA_VERSION)
   return add_ms_certsrv_ca_ver(data:extension["extnValue"]);

 return NULL;
}


digitalSignature        = 0x01;
nonRepudiation          = 0x02;
keyEncipherment         = 0x04;
dataEncipherment        = 0x08;
keyAgreement            = 0x10;
keyCertSign             = 0x20;
cRLSign                 = 0x40;
encipherOnly            = 0x80;
decipherOnly            = 0x100;

key_usage[digitalSignature]        = "Digital Signature";
key_usage[nonRepudiation]          = "Non Repudiation";
key_usage[keyEncipherment]         = "Key Encipherment";
key_usage[dataEncipherment]        = "Data Encipherment";
key_usage[keyAgreement]            = "Key Agreement";
key_usage[keyCertSign]             = "Key Cert Signature";
key_usage[cRLSign]                 = "CRL Signature";
key_usage[encipherOnly]            = "Encipher Only";
key_usage[decipherOnly]            = "Decipher Only";



function add_key_usage(data)
{
 local_var tmp, val, len, i, bit;

 bit = 1;
 tmp = NULL;

 while (bit <= 0x100)
 {
  if (data & bit)
  {
   if (tmp) tmp += ", ";
   
   tmp += key_usage[bit];
  }
  bit = bit << 1;
 }

 return add_string_nl(name:"Key Usage", data:tmp);
}


function add_extended_key_usage(data)
{
 local_var num, tmp, i, oid;

 num = max_index(data);
 tmp = NULL;

 for (i=0; i<num; i++)
 {
  oid = data[i];

  if (!isnull(oid_name[oid]))
    oid = oid_name[oid] + " (" + oid + ")";

  tmp += add_string(name:"Purpose#" + (i + 1), data:oid);
 }

 tmp += '\n';

 return tmp;
}


function add_general_name(name)
{
 local_var tmp;

 tmp = NULL;

 if (!isnull(name["directoryName"]))
   tmp += add_rdn_seq(seq:name["directoryName"]);

 if (!isnull(name["otherName"]))
   tmp += add_hex_string(name:"Other Name", data:name["otherName"]);

 if (!isnull(name["dNSName"]))
   tmp += add_string(name:"DNS", data:name["dNSName"]);

 if (!isnull(name["uniformResourceIdentifier"]))
   tmp += add_string(name:"URI", data:name["uniformResourceIdentifier"]);

 return tmp;
}


function add_crl_distribution_points(data)
{
 local_var dp, tmp, p, name;

 tmp = NULL;

 foreach dp (data)
 {
  p = dp["distributionPoint"];
  foreach name (p)
    tmp += add_general_name(name:name);
 }

 tmp += '\n';

 return tmp;
}


function add_authority_information_access(data)
{
 local_var tmp, num, i, ad, name, method;

 tmp = NULL;
 num = max_index(data);

 for (i=0; i<num; i++)
 {
  ad = data[i];

  method = ad["accessMethod"];
  if (!isnull(oid_name[method]))
    method = oid_name[method];

  tmp += add_string(name:"Method#" + (i+1), data:method);

  name = ad["accessLocation"];
  tmp += add_general_name(name:name);
 }

 tmp += '\n';

 return tmp;
}


function add_authority_key_identifier(data)
{
 local_var tmp, issuer, name;

 tmp = NULL;

 if (!isnull(data["keyIdentifier"]))
   tmp += add_hex_string(name:"Key Identifier", data:data["keyIdentifier"]);

 if (!isnull(data["authorityCertIssuer"]))
 {
  issuer = data["authorityCertIssuer"];
  foreach name (issuer)
    tmp += add_general_name(name:name);
 }

 if (!isnull(data["authorityCertSerialNumber"]))
   tmp += add_hex_string(name:"Serial Number", data:data["authorityCertSerialNumber"]);

 tmp += '\n';

 return tmp;
}


function add_subject_key_identifier(data)
{
 return add_hex_string_nl(name:"Subject Key Identifier", data:data);
}


function add_subject_alternative_name(data)
{
 local_var name, tmp;

 tmp = NULL;

 foreach name (data)
   tmp += add_general_name(name:name);

 tmp += '\n';

 return tmp;
}


function add_certificate_policies(data)
{
 local_var num, i, tmp, policy, pq, qualifier, qi, oid;

 tmp = NULL;

 num = max_index(data);
 for (i=0; i<num; i++)
 {
  policy = data[i];
  tmp += add_string(name:"Policy ID #" + (i+1), data:policy["policyIdentifier"]);

  pq = policy["policyQualifiers"];
  foreach qi (pq)
  {
   oid = qi["policyQualifierId"];
   if ( isnull(oid) ) continue;
   tmp += add_string(name:"Qualifier ID #" + (i+1), data:oid_name[oid] + " (" + oid+ ")");

   qualifier = qi["qualifier"];
   if (qi["policyQualifierId"] == OID_CPS_POINTER)
     tmp += add_string(name:"CPS URI", data:qualifier);
  }
 }

 tmp += '\n';

 return tmp;
}


function add_basic_constraints(data)
{
  local_var tmp;

  tmp = "";

  if (!isnull(data["ca"]))
  {
    if (data["ca"])
      tmp += add_string(name:"CA", data:"TRUE");
    else
      tmp += add_string(name:"CA", data:"FALSE");
  }

  if (!isnull(data["pathlen"]))
    tmp += add_string(name:"Path Length", data:data["pathlen"]);

  tmp += '\n';

  return tmp;
}


function add_ms_enroll_certtype(data)
{
  local_var tmp;

  tmp = "";

  if (!isnull(data["type"]))
    tmp += add_string(name:"Template", data:data["type"]);

  tmp += '\n';

  return tmp;
}


function add_ms_certsrv_ca_ver(data)
{
  local_var tmp;

  tmp = "";

  if (!isnull(data["cert"]))
    tmp += add_string(name:"Certificate Index", data:data["cert"]);

  if (!isnull(data["key"]))
    tmp += add_string(name:"Key Index", data:data["key"]);

  tmp += '\n';

  return tmp;
}


function dump_certificate(cert)
{
 local_var tbs, subject, report, issuer, validity, pki;
 local_var key, extensions, extension, name, bits, bytes, sig;
 local_var possible_name, nist_name, curve_info, hash;

 tbs = cert["tbsCertificate"];

 subject = tbs["subject"];

 report += add_string_nl(name:"Subject Name", data:"") +
           add_rdn_seq_nl(seq:subject);

 issuer = tbs["issuer"];

 report += add_string_nl(name:"Issuer Name", data:"") +
           add_rdn_seq_nl(seq:issuer);

 report += add_hex_string_nl(name:"Serial Number", data:tbs["serialNumber"]) +
           add_string_nl(name:"Version", data:tbs["version"]+1);

  # If RSA-PSS, the hash won't be present here, only "RSA-PSS Signature Scheme"
  # Users want to know the hash.
  if (tbs["signature"] == "1.2.840.113549.1.1.10")
  {
    hash = oid_name[cert.signatureAlgorithmParameters[0].value];
    if (!isnull(hash))
      report += add_string_nl(name:"Signature Algorithm", data:"RSA-PSS Signature Scheme with " + hash);
    else
      report += add_string_nl(name:"Signature Algorithm", data:"RSA-PSS Signature Scheme");
  }
  else
  {
    report += add_string_nl(name:"Signature Algorithm", data:oid_name[tbs["signature"]]);
  }

 validity = tbs["validity"];

 report += add_string(name:"Not Valid Before", data:validity["notBefore"]) +
           add_string_nl(name:"Not Valid After", data:validity["notAfter"]) ;

 pki = tbs["subjectPublicKeyInfo"];
 if (!isnull(pki))
 {
   report += add_string_nl(name:"Public Key Info", data:"") +
             add_string(name:"Algorithm", data:oid_name[pki[0]]);

   key = pki[1];
   if (!isnull(key))
   {
     # EC Public Key
     if (pki[0] == "1.2.840.10045.2.1")
     {
       foreach possible_name (keys(curve_nid.nist))
       {
         if (curve_nid.nist[possible_name] == curve_nid.oid[pki[2]])
         {
           nist_name = possible_name;
           break;
         }
       }
       # If we couldn't find the NIST name for the curve, just use the
       # OID, the user can look it up.
       if (!isnull(nist_name))
         report += add_string(name:"Elliptic Curve", data:nist_name);
       else
         report += add_string(name:"Elliptic Curve", data:"OID " + pki[2]);

       curve_info = ecc_curve_details(curve_nid:curve_nid.oid[pki[2]]);
       if (!isnull(curve_info))
         report += add_string(name:"Key Length", data:curve_info.order_bits + " bits");
       else
         report += add_string(name:"Key Length", data:"unknown");

       report += add_hex_string(name:"Public Key X", data:key[0]) +
                 add_hex_string_nl(name:"Public Key Y", data:key[1]) ;
     }
     # RSA Public Key
     else
     {
       bits = der_bit_length(key, 0);
       if (!isnull(bits))
         report += add_string(name:"Key Length", data:bits + " bits");

       report += add_hex_string(name:"Public Key", data:key[0]) +
                 add_hex_string_nl(name:"Exponent", data:key[1]) ;
     }
   }
 }

 sig = cert["signatureValue"];
 bytes = strlen(sig);
 if (ord(sig[0]) == 0)
   bytes--;

 report += add_string(name:"Signature Length", data:bytes + " bytes / " + (bytes * 8) + " bits");
 report += add_hex_string_nl(name:"Signature", data:sig) ;

 extensions = tbs["extensions"];
 if (!isnull(extensions))
 { 
  foreach extension (extensions)
  {
   name = extension["extnID"];
   if (!isnull(oid_name[name]))
     name = oid_name[name] + " (" + name + ")";

   report += add_string(name:"Extension", data:name) +
             add_string(name:"Critical", data:extension["critical"]) ;

   if (is_known_extension(id:extension["extnID"]))
     report += add_extension_data(extension:extension);
   else
     report += add_hex_string_nl(name:"Data", data:extension["extnValue"]);

   report += '\n';
  }
 }

 return report;
}

##
# Check whether a certificate is self-signed.
#
# @anonparam cert The certificate to examine.
#
# @return A boolean indicating whether the certificate is self-signed.
##
function is_self_signed()
{
  return (is_signed_by(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[0]));
}

##
# Check whether a certificate is a subscriber cert, defined as
# conforming to the validation criteria of the CA Browser Forum
# baseline requirements.
#
# @anonparam cert The certificate to examine
#
# @return A boolean indicating whether the certificate is a subscriber cert.
##
function is_subscriber_cert()
{
  local_var ext, policies, pol;

  var cert = _FCT_ANON_ARGS[0];
  if(is_self_signed(cert)) return FALSE;

  policies = NULL;
  foreach ext(cert["extensions"])
  {
    if(ext["extnID"] == EXTN_CERTIFICATE_POLICIES)
    {
      policies = ext["extnValue"];
      break;
    }
  }

  if(isnull(policies)) return FALSE;
  foreach pol(policies)
  {
    if((pol["policyIdentifier"] == CERTIFICATE_POLICY_EXTENDED_VALIDATION) ||
       (pol["policyIdentifier"] == CERTIFICATE_POLICY_DOMAIN_VAILDATION) ||
       (pol["policyIdentifier"] == CERTIFICATE_POLICY_ORG_VALIDATION) ||
       (pol["policyIdentifier"] == CERTIFICATE_POLICY_INDIVIDUAL_VALIDATION))  return TRUE;
  }

  return FALSE;
}

##
# Check whether a certificate is signed by another certificate.
#
# @anonparam subject The certificate which is signed.
# @anonparam issuer The certificate which may be the signer.
#
# @remark Only checks issuer, add optional signature checking later.
#
# @return A boolean indicating whether the subject is signed by the
#         issuer.
##
function is_signed_by()
{
  local_var ca, issuer, subj;

  # Process arguments.
  subj = _FCT_ANON_ARGS[0];
  issuer = _FCT_ANON_ARGS[1];

  # Make a list of known CAs containing only the certificate that
  # we're looking at.
  ca = make_list();
  ca[0] = issuer;

  return (find_issuer_idx(CA:ca, cert:subj) == 0);
}

##
# Formats a distinguished name.
#
# @anonparam chain An issuer or subject array from a certificate.
#
# @return A distinguished name.
##
function format_dn()
{
  local_var arr, dn, key, oids, pair;

  # Process arguments.
  arr = _FCT_ANON_ARGS[0];

  # List of OIDs used in DNs.
  oids = make_array(
    "0.9.2342.19200300.100.1.25", "DC",
    "1.2.840.113549.1.9.1", "E",
    "2.5.4.3", "CN",
    "2.5.4.6", "C",
    "2.5.4.7", "L",
    "2.5.4.8", "ST",
    "2.5.4.10", "O",
    "2.5.4.11", "OU"
  );

  # Convert OID and values to human-readable form.
  dn = make_list();

  foreach pair (arr)
  {
    key = oids[pair[0]];
    if (isnull(key))
      key = pair[0];

    dn = make_list(dn, key + "=" + pair[1]);
  }

  return join(dn, sep:"/");
}

##
# Finds an extension in an X.509 certificate.
#
# @param cert  An X.509 certificate to examine
# @param field The name of field in the extension, "extnValue" by
#              default
# @param id    The OID of the extension
#
# @return The extension requested.
##
function cert_get_ext(cert, field, id)
{
  local_var ext;

  # Sanity check parameters.
  if (isnull(cert))
    return NULL;

  if (isnull(id))
    return NULL;

  # Set defaults.
  if (isnull(field))
    field = "extnValue";

  foreach ext (cert["extensions"])
  {
    if (ext["extnID"] == id)
      return ext[field];
  }

  return NULL;
}

##
# Given a certificate or an issuer, search for the issuing
# certificate.
#
# @param CA     A list of arrays representing parsed certificates
# @param cert   An optional certificate to check the issuing
#               certificate against, will override the issuing
#               parameter
# @param issuer A list representing the subject to search for
#
# @return An integer indicating the index at which the issuing
#         certificate can be found in the CA list, or -1 if no match
#         could be found.
##
function find_issuer_idx(CA, cert, issuer, ignore_custom)
{
  local_var aki, f1, f2, i, j, match, sign, ski, subj;
  local_var n;

  if(isnull(ignore_custom)) ignore_custom = FALSE;

  # Sanity check parameters.
  if (isnull(CA))
    return NULL;

  if (isnull(cert) && isnull(issuer))
    return NULL;

  # The issuer is implied if we're given a certificate.
  if (cert)
  {
    if (!isnull(cert["tbsCertificate"]))
      cert = cert["tbsCertificate"];

    issuer = cert["issuer"];
  }

  n = max_index(CA);
  for (i = 0; i < n; i++)
  {
    sign = CA[i];
    if(sign["customCA"] && ignore_custom) continue;
    if (!isnull(sign["tbsCertificate"]))
      sign = sign["tbsCertificate"];

    subj = sign["subject"];

    # Skip certificates that don't have the right subject.
    if (!obj_cmp(subj, issuer))
      continue;

    # If we have no certificate to work with, no further matching is
    # possible. So we'll return the first cert we found with the right
    # subject.
    if (isnull(cert))
      return i;

    # Try to match up the Authority Key Identifier of the certificate
    # with the Subject Key Identifier of the signing certificate.
    # These extensions are optional and only found in X.509v3
    # certificates.
    if (cert["version"] != 2 || sign["version"] != 2)
      return i;

    aki = cert_get_ext(id:EXTN_AUTHORITY_KEY_IDENTIFIER, cert:cert);
    ski = cert_get_ext(id:EXTN_SUBJECT_KEY_IDENTIFIER, cert:sign);
    if (isnull(aki) || isnull(aki["keyIdentifier"]) || isnull(ski))
      return i;

    if (aki["keyIdentifier"] != ski)
      continue;

    return i;
  }

  return -1;
}

##
# Given a DER field, determine how many significant bits it contains.
#
# This function is primarily for calculating the components of
# cryptographic parameters.
#
# @anonparam ds  A string, list, or array.
# @anonparam idx If ds is a list or array, any number of idx arguments
#                can be specified for indexing into ds to get a field.
#
# @return An integer indicating the the number of significant bits in
#         the the DER field, or NULL if there was an error.
##
function der_bit_length()
{
  local_var blob, byte, i, len, mask, max;

  # Sanity check parameters.
  max = max_index(_FCT_ANON_ARGS);
  if (max <= 0)
    return NULL;

  # Traverse data structure to get data.
  blob = _FCT_ANON_ARGS[0];
  for (i = 1; i < max; i++)
  {
    if (typeof(blob) != "array")
      return NULL;

    blob = blob[_FCT_ANON_ARGS[i]];
  }

  # We can only perform the calculation on text.
  if (typeof(blob) !~ "^(data|string)$")
    return NULL;

  # Calculate the key length. Keys are stored such that the modulus
  # always has leading zeros, but those zeros do not contribute to the
  # key length.
  byte = ord(blob[0]);
  len = strlen(blob);

  # A leading NUL byte indicates that the key's bit length is a
  # multiple of 8.
  if (byte == 0)
    return (len - 1) * 8;

  # If there is no leading NUL byte, we know that the key's length is
  # not a multiple of 8. This tends to be a bug in the algorithm that
  # generated the key. Remove the leading zeros to determine the
  # actual length of the key.
  len *= 8;

  for (mask = 0x80; mask > 0x00; mask >>= 1)
  {
    # Stop shrinking the key length once we see the most significant
    # bit.
    if (byte & mask)
      break;

    len--;
  }

  return len;
}
