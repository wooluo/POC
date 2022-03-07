#TRUSTED 8746f53192bfe77657ff51afe6fb9e887c5f002bbf04a9bdd80ec948716339004cccc0d8d26e0c39aee4f70dccec0bfc4c6f79f7df9c727d9cc99e1b002aa1be02a38a69e8d181c0d1789438c3f0c5874eac6843fcb059890c02decf5d781344dcf2f7cd878b40cb3e63ab332a930b3b74d4885830df9537fe3711a5052892776e6aa0c2a82577a45fd61c8c380b2d445004edca60f7819826d1a3e599ae8af4d80e2559796b17616beca1cfdf5fc9c5b6e24853fe8790b65ff1e56585d0f0a523717eae197a916826ef57b6bf537300192697b0841f891d162f8c4c72080a69fb9064c350b4c00279fb641a8062558cf0e0ec2979c2dd388f0c29c9f1b5b35bb4c280950748b04a7a085e159060d86dd94169ce2b4756ebf35560764c4a84ef9740e4e749c993850d0c5ee018eb9837c7ceab803526880ca3a266184adde8458a0cc2aed98c89af4fc686cf7fe476de1c2487a54d914f4281b881d7afce7f1d36c85e3a7c3e5e82c017eafb95a51eca39881abf2a9850d2f29654265e622ca5a67b2db67859098a1a908910316b510ae8c522355a96347b729191e1348e4787a37ee58a886f699d0fd1318c137dfaefd27974eba7a97fb0acf6e38f7345d1b8478b8f5934c49d280ad1acd5e3416d1c989723669e507bd070154699bdad0e0a122879b0f11b1f20bfd08639867e4f667df4d49dd3b0c8fa44aa1e85fffe58a2
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.3
#
###


##
#
#  Namespace sshlib
#    Provides an encapsulated naming scope for sshlib functions and objects
#
##
namespace sshlib {

  global_var supported_compression_algs = "none";
  if(nasl_level() >= 6900) # see if our engine version supports Z_PARTIAL_FLUSH
    global_var supported_compression_algs = "zlib@openssh.com,zlib,none";

  # RFC 4419 Section 3
  global_var MAX_DH_GROUP_SIZE = 8192;
  global_var MIN_DH_GROUP_SIZE = 1024;

  ##
  # Diffie-Hellman group size preferred by this library
  ##
  global_var PRF_DH_GROUP_SIZE = 2048;

  ##
  # Namelists of KEX as defined by RFC 4253
  ##
  global_var KEX_NAME_LISTS = make_list(
   "kex_algorithms",
   "server_host_key_algorithms",
   "encryption_algorithms_client_to_server",
   "encryption_algorithms_server_to_client",
   "mac_algorithms_client_to_server",
   "mac_algorithms_server_to_client",
   "compression_algorithms_client_to_server",
   "compression_algorithms_server_to_client",
   "languages_client_to_server",
   "languages_server_to_client"
  );

  ##
  # Algorithms guaranteed to be supported by our implementation.
  # server_to_client algs are assumed to be the same as client_to_server
  # if they are not specified.
  #
  # Certificate versions must be listed  before their simple counterparts.
  # Failure to do so will break certificate authentication.
  ##
  ecdh_algs = "";
  ecdsa_algs = "";
  if(defined_func("ecc_curve_details"))
  {
    ecdh_algs =
      "ecdh-sha2-nistp521," +
      "ecdh-sha2-nistp384," +
      "ecdh-sha2-nistp256,";
    ecdsa_algs =
      "ecdsa-sha2-nistp256-cert-v01@openssh.com," +
      "ecdsa-sha2-nistp384-cert-v01@openssh.com," +
      "ecdsa-sha2-nistp521-cert-v01@openssh.com," +
      "ecdsa-sha2-nistp521," +
      "ecdsa-sha2-nistp384," +
      "ecdsa-sha2-nistp256,";
  }

  gcm_ciphers = "";
  if(defined_func("crypto_encrypt") && defined_func("crypto_decrypt"))
  {
     gcm_ciphers =
       "aes128-gcm@openssh.com," +
       "aes256-gcm@openssh.com,";
  }

  ##
  # SSH KEX algorithm names supported by this library
  ##
  global_var KEX_SUPPORTED_NAME_LISTS = make_array(
    "kex_algorithms",
      ecdh_algs +
      "diffie-hellman-group-exchange-sha256," +
      "diffie-hellman-group-exchange-sha1," +
      "diffie-hellman-group14-sha1," +
      "diffie-hellman-group14-sha256," +
      "diffie-hellman-group16-sha512," +
      "diffie-hellman-group18-sha512",
    "server_host_key_algorithms",
      ecdsa_algs +
      "x509v3-sign-rsa," +
      "ssh-rsa-cert-v01@openssh.com," +
      "ssh-dss-cert-v01@openssh.com," +
      "ssh-rsa-cert-v00@openssh.com," +
      "ssh-dss-cert-v00@openssh.com," +
      "ssh-rsa," + 
      "ssh-dss",
    "encryption_algorithms_client_to_server",
      "blowfish-cbc," +
      "aes128-ctr," +
      "aes192-ctr," +
      "aes256-ctr," +
      "aes128-cbc," +
      "aes192-cbc," +
      "aes256-cbc," +
      gcm_ciphers +
      "3des-cbc",
    "mac_algorithms_client_to_server",
      "hmac-sha1," +
      "hmac-sha2-256," +
      "hmac-sha2-512," +
      "hmac-sha2-256-etm@openssh.com," +
      "hmac-sha2-512-etm@openssh.com," +
      "umac-128-etm@openssh.com",
    "compression_algorithms_client_to_server",
      "none",
    "compression_algorithms_server_to_client",
      supported_compression_algs
  );

  ##
  # Diffie-Hellman p and g constants
  ##
  global_var DH_CONSTANT_GROUP_P_AND_G = make_array(
    "diffie-hellman-group1", make_array(
      "p", raw_string(
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
      "g", mkbyte(2)
    ),
    "diffie-hellman-group14", make_array(
      "p", raw_string(
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
      "g", mkbyte(2)
    ),
    "diffie-hellman-group16", make_array(
      "p", raw_string(
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
        0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
        0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
        0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
        0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
        0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
        0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
        0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
        0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
        0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
        0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
        0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
        0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
        0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
        0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
        0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
        0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
        0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
        0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
        0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
        0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
        0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
        0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
        0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
        0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
        0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
        0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
        0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
        0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
        0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
        0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
        0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
      "g", mkbyte(2)
    ),
    "diffie-hellman-group18", make_array(
      "p", raw_string(
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
        0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
        0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
        0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
        0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
        0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
        0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
        0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
        0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
        0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
        0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
        0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
        0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
        0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
        0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
        0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
        0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
        0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
        0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
        0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
        0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
        0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
        0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
        0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
        0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
        0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
        0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
        0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
        0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
        0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
        0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
        0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
        0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26,
        0xC1, 0xD4, 0xDC, 0xB2, 0x60, 0x26, 0x46, 0xDE,
        0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
        0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E,
        0xE5, 0xDB, 0x38, 0x2F, 0x41, 0x30, 0x01, 0xAE,
        0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
        0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18,
        0xDA, 0x3E, 0xDB, 0xEB, 0xCF, 0x9B, 0x14, 0xED,
        0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
        0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B,
        0x33, 0x20, 0x51, 0x51, 0x2B, 0xD7, 0xAF, 0x42,
        0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
        0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC,
        0xF0, 0x32, 0xEA, 0x15, 0xD1, 0x72, 0x1D, 0x03,
        0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
        0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82,
        0xB5, 0xA8, 0x40, 0x31, 0x90, 0x0B, 0x1C, 0x9E,
        0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
        0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE,
        0x0F, 0x1D, 0x45, 0xB7, 0xFF, 0x58, 0x5A, 0xC5,
        0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
        0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8,
        0x14, 0xCC, 0x5E, 0xD2, 0x0F, 0x80, 0x37, 0xE0,
        0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
        0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76,
        0xF5, 0x50, 0xAA, 0x3D, 0x8A, 0x1F, 0xBF, 0xF0,
        0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
        0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32,
        0x38, 0x7F, 0xE8, 0xD7, 0x6E, 0x3C, 0x04, 0x68,
        0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
        0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6,
        0xE6, 0x94, 0xF9, 0x1E, 0x6D, 0xBE, 0x11, 0x59,
        0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4,
        0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C,
        0xD8, 0xBE, 0xC4, 0xD0, 0x73, 0xB9, 0x31, 0xBA,
        0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00,
        0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED,
        0x25, 0x76, 0xF6, 0x93, 0x6B, 0xA4, 0x24, 0x66,
        0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68,
        0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78,
        0x23, 0x8F, 0x16, 0xCB, 0xE3, 0x9D, 0x65, 0x2D,
        0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9,
        0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07,
        0x13, 0xEB, 0x57, 0xA8, 0x1A, 0x23, 0xF0, 0xC7,
        0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B,
        0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD,
        0xFA, 0x9D, 0x4B, 0x7F, 0xA2, 0xC0, 0x87, 0xE8,
        0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A,
        0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6,
        0x6D, 0x2A, 0x13, 0xF8, 0x3F, 0x44, 0xF8, 0x2D,
        0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36,
        0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1,
        0x64, 0xF3, 0x1C, 0xC5, 0x08, 0x46, 0x85, 0x1D,
        0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1,
        0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73,
        0xFA, 0xF3, 0x6B, 0xC3, 0x1E, 0xCF, 0xA2, 0x68,
        0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92,
        0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7,
        0x88, 0x9A, 0x00, 0x2E, 0xD5, 0xEE, 0x38, 0x2B,
        0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47,
        0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA,
        0x9E, 0x30, 0x50, 0xE2, 0x76, 0x56, 0x94, 0xDF,
        0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71,
        0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
      "g", mkbyte(2)
    )
  );

  ##
  #
  # Object kex_handler
  #   Encapsulates functions and state for handling SSH key exchange (KEX)
  #
  ##

  object kex_handler
  {
    var session;
    var obj = 'kex_handler';
    var kex_alg; # selected key exchange algorithm
    var server_host_key_alg; # selected algorithm for public / private key exchange
    var mac_alg_c_to_s; # selected hashing algorithm - client to server
    var mac_alg_s_to_c; # selected hashing algorithm - server to client
    var encryption_alg_c_to_s; # selected encryption algorithm - client to server
    var encryption_alg_s_to_c; # selected encryption algorithm - server to client
    var kex_supported_namelists;
    var dh_local_priv, dh_local_pub;
    var dh_remote_pub;
    var shared_secret;
    var host_cert;
    var remote_init_pkt = '';
    var our_init_pkt = '';
    var auth_alg;
    var auth_hash_alg;
    var dsa_p = NULL;
    var dsa_q = NULL;
    var dsa_g = NULL;
    var dsa_y = NULL;
    var rsa_e = NULL;
    var rsa_n = NULL;
    var dh_p, dh_g;
    var kex_recv_namelists;
    var id;
    var remote_cookie;
    var our_cookie;

    var ecdh_local_priv;
    var ecdh_local_pub;
    var ecdh_remote_pub;
    var ecdh_hash_alg;
    var ecdh_curve;
    var ecdh_curve_info;
    var ecdsa_sig_hash_cb;

    var keyblob_ecdsa_curve_info, keyblob_ecdsa_nid, keyblob_q_s_x, keyblob_q_s_y, keyblob_q_s;

    ##
    # Constructor function for the kex_handler object
    #
    # @anonparam <First:session> sshlib session object
    # @category SSH
    ##
    function kex_handler()
    {
      session = _FCT_ANON_ARGS[0];
      if(isnull(session))
        exit(1, "A valid session was not passed to the kex_handler constructor.");
    }

    ##
    # Assigns the anonymous argument to dh_remote_pub
    #
    # @anonparam <First> Remote Diffie-Hellman public key
    # @category SSH
    ##
    public function set_dh_remote_pub() {dh_remote_pub = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to shared_secret
    #
    # @anonparam <First> Diffie-Hellman shared secret
    # @category SSH
    ##
    public function set_shared_secret()
    {
      var fn = obj +'.set_shared_secret'; 
      session.dbg_log(fn:fn, level:DEBUG2, message:"shared secret computed: ", ddata:_FCT_ANON_ARGS[0]);
      shared_secret = _FCT_ANON_ARGS[0];
    }

    ##
    # Assigns the anonymous argument to host_cert
    #
    # @anonparam <First> Remote host SSH certificate, used in place of a public key
    # @category SSH
    ##
    public function set_host_cert()       {host_cert = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to remote_init_pkt
    #
    # @anonparam <First> KEX init packet sent by the remote host
    # @category SSH
    ##
    public function set_remote_init_pkt() {remote_init_pkt = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to our_init_pkt
    #
    # @anonparam <First> KEX init packet sent by us
    # @category SSH
    ##
    public function set_our_init_pkt()    {our_init_pkt    = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to auth_alg
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_auth_alg()        {auth_alg = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to auth_hash_alg
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_auth_hash_alg()   {auth_hash_alg = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to dsa_p
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_dsa_p()  {dsa_p = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to dsa_q
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_dsa_q()  {dsa_q = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to dsa_g
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_dsa_g()  {dsa_g = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to dsa_y
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_dsa_y()  {dsa_y = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to rsa_e
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_rsa_e()  {rsa_e = _FCT_ANON_ARGS[0];}

    ##
    # Assigns the anonymous argument to rsa_n
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_rsa_n()  {rsa_n = _FCT_ANON_ARGS[0];}

    ##
    # Assigns p and g parameters to diffie-hellman members dh_p and dh_g
    #
    # @param p
    # @param g
    # @category SSH
    ##
    public function set_dh_groups(p, g)
    {
      dh_p = p;
      dh_g = g;
    }

    ##
    # Assigns the anonymous argument to kex_recv_namelists
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_kex_recv_namelists()
    {
      kex_recv_namelists      = _FCT_ANON_ARGS[0];
    }

    ##
    # Assigns the anonymous argument to id
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_id()                      { if(isnull(id)) { id     = _FCT_ANON_ARGS[0]; } }

    ##
    # Assigns the anonymous argument to remote_cookie
    #
    # @anonparam <First>
    # @category SSH
    ##
    public function set_remote_cookie()           { remote_cookie           = _FCT_ANON_ARGS[0];}

    ##
    # Generates a random sequence of bytes to serve as our SSH cookie
    #
    # @category SSH
    ##
    public function generate_ssh_cookie()
    {
      our_cookie = "";
      local_var i;
      for (i = 0; i < 16; i++)
        our_cookie = our_cookie + mkbyte(rand() % 256);
    }

    ##
    # Sets the chosen algorithm for the namelist provided
    #
    # @anonparam <First>  the namelist that the algorithm was chosen from
    # @anonparam <Second> the chosen algorithm
    #
    # @category SSH
    ##
    public function set_algorithm()
    {
      local_var namelist = _FCT_ANON_ARGS[0];
      local_var algo     = _FCT_ANON_ARGS[1];

      if("kex_" >< namelist)
        kex_alg = algo;
      else if("server_host_" >< namelist)
        server_host_key_alg = algo;

      else if("encryption_" >< namelist && "client_to_server">< namelist)
        encryption_alg_c_to_s = algo;
      else if("encryption_" >< namelist && "server_to_client">< namelist)
        encryption_alg_s_to_c = algo;

      else if("mac_" >< namelist && "client_to_server" >< namelist)
        mac_alg_c_to_s = algo;
      else if("mac_" >< namelist && "server_to_client" >< namelist)
        mac_alg_s_to_c = algo;

      else if("compression_" >< namelist && "client_to_server" >< namelist)
        session.set_compression_alg(mode:MODE_OUT, alg:algo);
      else if("compression_" >< namelist && "server_to_client" >< namelist)
        session.set_compression_alg(mode:MODE_IN, alg:algo);
      else
        session.set_error("kex_handler: unrecognized namelist '"+namelist+"' sent to set_algorithm()");
    }

    ##
    # Selects the first supported algorithm from the client's supported namelist that the server
    # also supports in their namelist
    #
    # @anonparam <First> name of the namelist that a matching algorithm should be returned for
    #
    # @return    an algorithm supported by both the client and the server for the specified
    #            namelist if one was found, otherwise NULL
    #
    # @remark    This function expects that kex_supported_namelists[] has already been set
    #            by set_supported_namelists() and that kex_recv_namelists[] has already been
    #            set by set_kex_recv_namelists()
    # @category SSH
    ##
    public function select_algorithm(namelist)
    {
      local_var fn = obj+'.select_algorithm';
      local_var supported_list = split(kex_supported_namelists[namelist], sep:",", keep:FALSE);
      local_var selected = NULL;
      local_var i;

      if(isnull(supported_list))
      {
        session.set_error("kex_handler: no value for "+namelist+" in kex_supported_namelists");
        return NULL;
      }
      if(isnull(kex_recv_namelists[namelist]))
      {
        session.set_error("kex_handler: no value for "+namelist+" in kex_recv_namelists");
        return NULL;
      }

      for (i=0; i<max_index(supported_list); i++)
      {
        selected = supported_list[i];
        if(kex_recv_namelists[namelist] =~ "(^|,)" + selected + "(,|$)")
          break;

        selected = NULL; # if nothing is found, we want selected NULL
      }

      if(!isnull(selected))
        session.dbg_log(fn:fn, level:DEBUG2, message:"kex_handler : selected " + selected + " for namelist " + namelist + '\n');

      return selected;
    }

    ##
    # Assigns the anonymous argument to kex_supported_namelists. The anonymous argument is
    # expected to be an array. If only a client-to-server namelist is specified in the array,
    # then the associated server-to-client namelist is set to the same list of algorithms
    #
    # @anonparam <First> an array of name-lists and a comma-separated list of client-supported
    #                    algorithms for each
    #
    # @category SSH
    ##
    public function set_supported_namelists()
    {
      kex_supported_namelists = _FCT_ANON_ARGS[0];

      local_var namelist, tmp_namelist;

      # if we don't specify a server to client namelist, use what we have from
      # client to server
      foreach namelist (KEX_NAME_LISTS)
      {
        if("server_to_client" >< namelist && isnull(kex_supported_namelists[namelist]))
        {
          tmp_namelist = namelist - "server_to_client" + "client_to_server";
          kex_supported_namelists[namelist] = kex_supported_namelists[tmp_namelist];
        }
      }
    }

    ##
    # Extracts namelists from a KEX_INIT packet sent by the remote host.
    #
    # @anonparam <First> A KEX_INIT packet.
    # @return Returns a dictionary of comma delimited namelists
    # @remark Namelists defined in https://www.ietf.org/rfc/rfc4253.txt
    # @category SSH
    ##
    public function kex_pkt_parse_namelists()
    {
      local_var pkt = _FCT_ANON_ARGS[0];
      # Skip past kex server cookie
      local_var cur_pos = 16;

      local_var namelists = make_array();
      local_var namelist;
      local_var value;

      # parse namelists into an array
      foreach namelist (KEX_NAME_LISTS)
      {
        # Sanity check
        if(cur_pos >= strlen(pkt.payload))
          return NULL;
        namelists[namelist] = get_ssh_string(buffer:pkt.payload, pos:cur_pos);
        # Failed to parse list
        if(isnull(namelists[namelist]))
          return NULL;
        cur_pos += 4 + strlen(namelists[namelist]);
      }
      return namelists;
    }

    ##
    # Validates a public key received as part of diffie-hellman exchange.
    #
    # @param <key>
    # @param <p>
    # @return Returns TRUE (1) if the key is valid and FALSE (0) otherwise.
    # @remark This function uses the validation algorithm from section 2.1.5 of https://tools.ietf.org/html/rfc2631
    # @category SSH
    ##
    function dh_valid_key(key, p)
    {
      local_var val,i;

      if (ord(key[0]) > 0x80)
        return 0;

      val = 0;
      for(i=0;i<strlen(key);i++)
      {
        val = val + ord(key[i]);
        if (val > 1)
          break;
      }

      # ok if key < p
      if ((val>1) && (bn_cmp(key1:key,key2:p) == -1))
        return 1;

      return 0;
    }

    ##
    # Generates a ECC public/private key pair for a given elliptic curve.
    #
    # @param <nid> OpenSSL NID representing an elliptic curve.
    # @return Returns TRUE if the function succeeds in creating a elliptic curve key pair, FALSE otherwise.
    # @category SSH
    ##
    public function ecdh_gen_secret_key(nid)
    {
      ecdh_local_priv = ecc_generate_secret_key(curve_nid: nid);
      ecdh_curve_info = ecc_curve_details(curve_nid: nid);
      if(isnull(ecdh_curve_info)) return FALSE;

      if(ecdh_curve_info.order_bits <= 256) ecdh_hash_alg = "sha256";
      else if(ecdh_curve_info.order_bits > 256 && ecdh_curve_info.order_bits <= 384) ecdh_hash_alg = "sha384";
      else if(ecdh_curve_info.order_bits > 384 && ecdh_curve_info.order_bits <= 521) ecdh_hash_alg = "sha512";
      else return FALSE;

      ecdh_local_pub = ecc_scalar_multiply(scalar:ecdh_local_priv, curve_nid:nid);
      if(isnull(ecdh_local_pub)) return FALSE;

      ecdh_local_pub.x = ecc_fe2osp(curve_nid: nid, element: ecdh_local_pub.x);
      ecdh_local_pub.y = ecc_fe2osp(curve_nid: nid, element: ecdh_local_pub.y);

      ecdh_curve = nid;
      return TRUE;
    }

    ##
    # Generates a public/private key pair for diffie-hellman key exchange.
    #
    # @return Returns TRUE if the function succeeds in creating a key pair, FALSE otherwise.
    # @category SSH
    ##
    public function dh_gen_key()
    {
      local_var tries,need, dh_local_priv_tmp, dh_local_pub_tmp;

      if(isnull(session.new_cipherset)) return FALSE;

      need = session.new_cipherset.get_ciphers_need();

      this.dh_local_pub  = '';
      this.dh_local_priv = '';
      dh_local_pub_tmp = '';
      dh_local_priv_tmp = '';
      tries    = 0;

      for (tries = 0; tries < 10; tries++)
      {
        dh_local_priv_tmp = bn_random(need:(need*2));
        if(!dh_local_priv_tmp) return FALSE;
        dh_local_pub_tmp = dh_generate_key(p:dh_p, g:dh_g, priv:dh_local_priv_tmp);
        if(!dh_local_pub_tmp) return FALSE;
        if(dh_valid_key(key:dh_local_pub_tmp, p:dh_p))
          break;
      }
      if (tries == 10) return FALSE;
      this.dh_local_pub  = dh_local_pub_tmp;
      this.dh_local_priv = dh_local_priv_tmp;
      return TRUE;
    }

    ##
    # Generates an encryption key from a shared secret and exchange hash value.
    #
    # @param <hash>         A hash of the key exchange parameters.
    # @param <session_id>   Session ID
    # @param <shared>       Shared secret.
    # @param <hash_type>    Algorithm used to calculate the exchange hash
    # @param <max>          Maximum length of the derived key
    # @return Returns the derived key.
    # @remark Described in https://tools.ietf.org/html/rfc4253 section 7.2
    # @category SSH
    ##
    public function ssh_derive_keys(hash, session_id, shared, hash_type, max)
    {
      local_var h, i, k, key, s, x;
      if (isnull(hash_type) || (hash_type != "sha1" && hash_type != "sha256" && hash_type != "sha384" && hash_type != "sha512"))
        hash_type = "sha1";

      # Convert variables to match formulas.
      h = hash;
      s = mk_ssh_mpint(shared);
      x = ord("A");
      key = make_list();

      for (i = 0; i < 6; i++)
      {
        # Derive the key.
        if (hash_type == "sha1")
          k = SHA1(s + h + mkbyte(x + i) + session_id);
        else if (hash_type == "sha256")
          k = SHA256(s + h + mkbyte(x + i) + session_id);
        else if (hash_type == "sha384")
          k = SHA384(s + h + mkbyte(x + i) + session_id);
        else if (hash_type == "sha512")
          k = SHA512(s + h + mkbyte(x + i) + session_id);

        # Lengthen the key if required.
        while(strlen(k) < max)
        {
          if (hash_type == "sha1")
            k += SHA1(s + h + k);
          else if (hash_type == "sha256")
            k += SHA256(s + h + k);
          else if (hash_type == "sha384")
            k += SHA384(s + h + k);
          else if (hash_type == "sha512")
            k += SHA512(s + h + k);
        }

        key[i] = substr(k, 0, max - 1);
      }

      #         MODE OUT  MODE IN
      # enc.iv    0         1
      # enc.key   2         3
      # mac.key   4         5

      return key;
    }

    ##
    # Finalize KEX by parsing and validating the host certificate, computing a shared secret and encryption keys.
    #
    # @return Returns TRUE if the function succeeds, otherwise returns NULL.
    # @category SSH
    ##
    public function parse_host_cert()
    {
      local_var last_pkt, key_blob, algo, host_cert, pos, tmp, signed_hash,
                correct, hash, to_hash, shared, tmp_offset, cert_info, q_s,
                q_s_x, q_s_y, cert_sig;

      local_var fn = obj + '.parse_host_cert';

      last_pkt = session.last_packet;
      key_blob = get_ssh_string(buffer:last_pkt.payload, pos:0);
      if(empty_or_null(key_blob))
        return session.set_error("Remote host key blob is empty or NULL.");
      session.set_remote_host_key(key_blob);

      if(server_host_key_alg != "x509v3-sign-rsa" && "-cert-" >!< server_host_key_alg)
      {
        algo = get_ssh_string(buffer:key_blob, pos:0);
        pos = 4 + strlen(algo);
      }
      else
      {
        algo = server_host_key_alg;
      }

      # Log the host key to the KB
      set_kb_blob(name:SSH_LIB_KB_PREFIX +
          session.get_kb_connection_id() + '/hostkey/' + algo,
          value:key_blob);

      ## branch has been merged with the dbg_log branch. 
      session.dbg_log(fn:fn, level:DEBUG3, message:'saving hostkey to kb: ', base64:key_blob);

      session.dbg_log(fn:fn, level:DEBUG2, message:"host certificate uses " + algo + ' signature algorithm\n');

      if(algo == "ssh-rsa" || algo == "ssh-dss")
      {
        if(algo == "ssh-rsa")
        {
          set_auth_alg("rsa");

          tmp = get_ssh_mpint (buffer:key_blob, pos:pos);
          if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
          {
            session.set_error("Error parsing host RSA e parameter.");
            return NULL;
          }
          set_rsa_e(tmp['value']);
          pos += tmp['length'];
          tmp = get_ssh_mpint (buffer:key_blob, pos:pos);
          if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
          {
            session.set_error("Error parsing host RSA n parameter.");
            return NULL;
          }
          pos += tmp['length'];
          set_rsa_n(tmp['value']);
        }
        else
        {
          set_auth_alg("dsa");

          tmp = get_ssh_mpint (buffer:key_blob, pos:pos);
          if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
          {
            session.set_error("Error parsing host DSA p parameter.");
            return NULL;
          }
          pos += tmp['length'];
          set_dsa_p(tmp['value']);

          tmp = get_ssh_mpint (buffer:key_blob, pos:pos);
          if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
          {
            session.set_error("Error parsing host DSA q parameter.");
            return NULL;
          }
          pos += tmp['length'];
          set_dsa_q(tmp['value']);

          tmp = get_ssh_mpint (buffer:key_blob, pos:pos);
          if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
          {
            session.set_error("Error parsing host DSA g parameter.");
            return NULL;
          }
          pos += tmp['length'];
          set_dsa_g(tmp['value']);

          tmp = get_ssh_mpint (buffer:key_blob, pos:pos);
          if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
          {
            session.set_error("Error parsing host DSA y parameter.");
            return NULL;
          }

          pos += tmp['length'];
          set_dsa_y(tmp['value']);
        }
      }
      else if("ssh-rsa-cert-" >< algo || "ssh-dss-cert-" >< algo)
      {
        host_cert = key_blob;
        cert_info = parse_ssh_cert(cert:host_cert);
        if(isnull(cert_info))
        {
          session.set_error("Error parsing host SSH certificate.");
          return NULL;
        }

        if(cert_info["signature_type"] !~ "^ssh-(rsa|dss)$" && cert_info['signature_type'] !~ '^ecdsa')
        {
          session.set_error("Unsupported certificate signature type : " + cert_info["signature_type"]);
        }

        set_host_cert(cert_info);

        if("-rsa-" >< algo)
        {
          set_auth_alg("rsa");
          set_rsa_e(cert_info["e"]);
          set_rsa_n(cert_info["n"]);
        }
        else
        {
          set_auth_alg("dsa");
          set_dsa_p(cert_info["p"]);
          set_dsa_q(cert_info["q"]);
          set_dsa_g(cert_info["g"]);
          set_dsa_y(cert_info["y"]);
        }
      }
      else if(algo == "x509v3-sign-rsa")
      {
        set_auth_alg("rsa");
        var res = parse_der_cert(cert:key_blob);
        var key_info = res['tbsCertificate']['subjectPublicKeyInfo'];
        var i;
        for(i=0; i<max_index(key_info); i += 2)
        {
          if(key_info[i] == '1.2.840.113549.1.1.1') # RSA encryption
          {
            set_rsa_n(key_info[i+1][0]);
            set_rsa_e(key_info[i+1][1]);

            break;
          }
        }
      }
      else if(algo =~ "^ecdsa-sha2-nistp(256|384|521).*$")
      {
        if("-cert-" >< algo)
        {
          host_cert = key_blob;
          cert_info = parse_ssh_cert(cert:host_cert);
          if(isnull(cert_info))
          {
            session.set_error("Error parsing host SSH certificate.");
            return NULL;
          }

          if(cert_info['signature_type'] !~ "^ssh-(rsa|dss)$" && cert_info['signature_type'] !~ '^ecdsa')
          {
            session.set_error("Unsupported certificate signature type : " + cert_info["signature_type"]);
          }

          set_auth_alg(algo);
          set_host_cert(cert_info);
          keyblob_q_s = cert_info["public_key"];
        }
        else
        {
          set_auth_alg(algo);
          var keyblob_q_id = get_ssh_string(buffer:key_blob, pos:pos);
          pos += strlen(keyblob_q_id) + 4;
          keyblob_q_s = get_ssh_string(buffer:key_blob, pos:pos);
        }

        if(algo =~ "^ecdsa-sha2-nistp256")
        {
          keyblob_ecdsa_nid = curve_nid.nist.P256;
          ecdsa_sig_hash_cb = @SHA256;
        }
        else if(algo =~ "^ecdsa-sha2-nistp384")
        {
          keyblob_ecdsa_nid = curve_nid.nist.P384;
          ecdsa_sig_hash_cb = @SHA384;
        }
        else if(algo =~ "^ecdsa-sha2-nistp521")
        {
          keyblob_ecdsa_nid = curve_nid.nist.P521;
          ecdsa_sig_hash_cb = @SHA512;
        }

        keyblob_ecdsa_curve_info = ecc_curve_details(curve_nid:keyblob_ecdsa_nid);
        if(isnull(keyblob_ecdsa_curve_info))
        {
          session.set_error("Failed to retrieve ECC curve details for : " + algo);
          return NULL;
        }

        keyblob_q_s_x = substr(keyblob_q_s, 1, (keyblob_ecdsa_curve_info.order_bits + 7) / 8);
        keyblob_q_s_y = substr(keyblob_q_s, 1 + ((keyblob_ecdsa_curve_info.order_bits + 7) / 8),  ((keyblob_ecdsa_curve_info.order_bits + 7) / 8) * 2);
      }
      else
      {
        session.set_error("Unsupported host key algorithm: " + algo);
        return NULL;
      }

      tmp_offset = 4 + strlen(key_blob);


      if(kex_alg =~ "^ecdh-sha2-")
      {
        q_s = get_ssh_string(buffer:last_pkt.payload, pos:tmp_offset);
        q_s_x = substr(q_s, 1, (ecdh_curve_info.order_bits + 7) / 8);
        q_s_y = substr(q_s, 1 + ((ecdh_curve_info.order_bits + 7) / 8),  ((ecdh_curve_info.order_bits + 7) / 8) * 2);

        session.dbg_log(fn:fn, level:DEBUG3, message:"ecdh_q_s: " + hexstr(q_s));
        session.dbg_log(fn:fn, level:DEBUG3, message:"ecdh_q_s_x: " + hexstr(q_s_x));
        session.dbg_log(fn:fn, level:DEBUG3, message:"ecdh_q_s_y: " + hexstr(q_s_y));

        tmp_offset += 4 + strlen(q_s);
      }
      else
      {
        set_dh_remote_pub(get_ssh_string(buffer:last_pkt.payload, pos:tmp_offset));
        if(!dh_valid_key(key:dh_remote_pub, p:dh_p))
        {
          session.set_error("Server DH public key is not valid!");
          return NULL;
        }
        tmp_offset += 4 + strlen(dh_remote_pub);
      }

      signed_hash = get_ssh_string(buffer:last_pkt.payload, pos:tmp_offset);

      if(session.debug > DEBUG2)
        spad_log(message:"exchange hash signature: " + hexstr(signed_hash));

      if(kex_alg =~ "^ecdh-sha2-")
      {
        var tmp_secret = bn_mul(ecdh_local_priv, ecdh_curve_info.cofactor);
        shared = ecc_scalar_multiply(scalar    : tmp_secret,
                                     curve_nid : ecdh_curve,
                                     x         : q_s_x,
                                     y         : q_s_y);
        shared = shared.x;
      }
      else
      {
        shared = dh_compute_key(p             : dh_p,
                                g             : dh_g,
                                dh_server_pub : dh_remote_pub,
                                pub_key       : dh_local_pub,
                                priv_key      : dh_local_priv);
      }

      if (!shared)
      {
        session.set_error("Error during shared secret computing.");
        return NULL;
      }

      set_shared_secret(shared);

      # hash data
      to_hash =
      mk_ssh_string(session.local_version) +     # client version
      mk_ssh_string(session.remote_version) +    # server version
      mkdword(strlen(our_init_pkt) + 1, order:BYTE_ORDER_BIG_ENDIAN) +
      mkbyte(PROTO_SSH_MSG_KEXINIT) +
      our_init_pkt +

      mkdword(strlen(remote_init_pkt) + 1, order:BYTE_ORDER_BIG_ENDIAN) +
      mkbyte(PROTO_SSH_MSG_KEXINIT) +
      remote_init_pkt +

      # mpint ??
      mk_ssh_string(key_blob); # server host key blob

      if (kex_alg == 'diffie-hellman-group-exchange-sha1' || kex_alg == 'diffie-hellman-group-exchange-sha256')
      {
        to_hash +=
        # minimal size in bits of group
        mkdword(MIN_DH_GROUP_SIZE, order:BYTE_ORDER_BIG_ENDIAN) +
        # preferred size in bits of group
        mkdword(PRF_DH_GROUP_SIZE, order:BYTE_ORDER_BIG_ENDIAN) +
        # maximal size in bits of group
        mkdword(MAX_DH_GROUP_SIZE, order:BYTE_ORDER_BIG_ENDIAN) +
        mk_ssh_mpint(buffer:dh_p) + # p
        mk_ssh_mpint(buffer:dh_g);  # g
      }

      if(kex_alg =~ "^ecdh-sha2-")
      {
        to_hash +=
          mk_ssh_string('\x04' + ecdh_local_pub.x + ecdh_local_pub.y) +
          mk_ssh_string(q_s) +
          mk_ssh_mpint(buffer:shared);         # shared bignum
      }
      else
      {
        to_hash +=
        mk_ssh_mpint(buffer:dh_local_pub) +  # public key bignum
        mk_ssh_mpint(buffer:dh_remote_pub) + # server dh public key bignum
        mk_ssh_mpint(buffer:shared);         # shared bignum
      }

      if(!isnull(ecdh_hash_alg))
      {
        if(ecdh_hash_alg == "sha256") hash = SHA256(to_hash);
        else if(ecdh_hash_alg == "sha384") hash = SHA384(to_hash);
        else if(ecdh_hash_alg == "sha512") hash = SHA512(to_hash);
        set_auth_hash_alg(ecdh_hash_alg);
      }
      else if (kex_alg =~ "-sha1$")
      {
        hash = SHA1(to_hash);
        set_auth_hash_alg("sha1");
      }
      else if (kex_alg =~ "-sha256$")
      {
        hash = SHA256(to_hash);
        set_auth_hash_alg("sha256");
      }
      else if (kex_alg =~ "-sha512$")
      {
        hash = SHA512(to_hash);
        set_auth_hash_alg("sha512");
      }
      else
      {
        session.set_error("Unsupported key exchange algorithm hash: " + kex_alg);
        return NULL;
      }
      if (auth_alg == "rsa")
      {
        correct = ssh_rsa_verify(e:rsa_e,
                                 n:rsa_n,
                                 signature:signed_hash,
                                 data:hash);
      }
      else if (auth_alg == "dsa")
      {
        correct = ssh_dss_verify(p:dsa_p,
                                 q:dsa_q,
                                 g:dsa_g,
                                 pub:dsa_y,
                                 signature:signed_hash,
                                 data:hash);
      }
      else if(auth_alg =~ "^ecdsa")
      {
        cert_sig = decode_ecdsa_signature(signed_hash);

        if(isnull(cert_sig))
        {
          session.set_error("Failed to decode server's ECDSA signature.");
          return NULL;
        }

        var sig_r = cert_sig['sig_r'];
        var sig_s = cert_sig['sig_s'];

        correct = ecdsa_verify(msg       : hash,
                               x         : keyblob_q_s_x,
                               y         : keyblob_q_s_y,
                               r         : sig_r,
                               s         : sig_s,
                               hash      : ecdsa_sig_hash_cb,
                               curve_nid : keyblob_ecdsa_nid);
      }

      if (!correct)
      {
        session.set_error("Server's signature is not valid!");
        return NULL;
      }
      set_id(hash);

      var keys = ssh_derive_keys(hash:hash,
                                 shared:shared_secret,
                                 session_id:id,
                                 hash_type:auth_hash_alg,
                                 max: session.new_cipherset.get_ciphers_need());

      session.new_cipherset.set_enc_keys(keys);

      return TRUE;
    }

    ##
    # Generates data used to verify the signature in an SSH RSA certificate
    #
    # @anonparam <First> the certificate that contains the signature to verify (this should be in the format returned by parse_ssh_cert())
    # @return data used to verify the signature in an SSH RSA certificate
    # @category SSH
    ##
    function generate_ssh_rsa_cert_sig_data()
    {
      local_var cert, data, tmp, tmp_data;
      tmp_data = '';

      cert = _FCT_ANON_ARGS[0];
      if (isnull(cert)) return NULL;

      if (cert["key_type"] == "ssh-rsa-cert-v00@openssh.com")
      {
        data =
        mk_ssh_string(cert["key_type"]) +
        mk_ssh_mpint(cert["e"]) +
        mk_ssh_mpint(cert["n"]) +
        cert["type"] +
        mk_ssh_string(cert["key_id"]);

        foreach tmp (cert["valid_principals"])
          tmp_data += mk_ssh_string(tmp);

        data +=
          mk_ssh_string(tmp_data) +
          cert["valid_after"] +
          cert["valid_before"] +
          mk_ssh_string(cert["constraints"]) +
          mk_ssh_string(cert["nonce"]) +
          mk_ssh_string(cert["reserved"]) +
          mk_ssh_string(cert["signature_key"]);
      }
      else
      {
        data =
          mk_ssh_string(cert["key_type"]) +
          mk_ssh_string(cert["nonce"]) +
          mk_ssh_mpint(cert["e"]) +
          mk_ssh_mpint(cert["n"]) +
          cert["serial"] +
          cert["type"] +
          mk_ssh_string(cert["key_id"]);

        foreach tmp (cert["valid_principals"])
          tmp_data += mk_ssh_string(tmp);

        data +=
          mk_ssh_string(tmp_data) +
          cert["valid_after"] +
          cert["valid_before"] +
          mk_ssh_string(cert["critical_options"]) +
          mk_ssh_string(cert["extensions"]) +
          mk_ssh_string(cert["reserved"]) +
          mk_ssh_string(cert["signature_key"]);
      }

      return data;
    }

    ##
    # Verifies that the signature of the given SSH certificate is valid.
    # Currently only RSA, DSA and ECDSA certificates and signatures are supported.
    #
    # @anonparam <First> the certificate that contains the signature to verify (this should be in the format returned by parse_ssh_cert())
    # @return TRUE if the signature is valid,
    #         FALSE if it is invalid or the cert/signature type is unknown or unsupported
    # @category SSH
    ##
    public function verify_ssh_cert_signature()
    {
      local_var cert, data, ca_key, ca_sig;
      cert = _FCT_ANON_ARGS[0];

      if (cert["key_type"] =~ "^ssh-rsa-cert-")
        data = generate_ssh_rsa_cert_sig_data(cert);
      else if (cert["key_type"] =~ "^ssh-dss-cert-")
        data = generate_ssh_dsa_cert_sig_data(cert);
      else if (cert["key_type"] =~ "^ecdsa-sha2-nistp.*-cert-")
        data = generate_ssh_ecdsa_cert_sig_data(cert);
      else
      {
        session.set_error("Unable to verify the certificate signature (type "+cert["key_type"]+" is currently unsupported).");
        return FALSE; # unknown/unsupported cert key type
      }

      ca_key = decode_ssh2_public_key(cert["signature_key"]);

      if (isnull(ca_key)) return FALSE;
      if (ca_key["type"] == "ssh-rsa")
        return ssh_rsa_verify(e:ca_key["e"], n:ca_key["n"], signature:cert["signature"], data:data);
      else if (ca_key["type"] == "ssh-dss")
        return ssh_dss_verify(p:ca_key["p"], q:ca_key["q"], g:ca_key["g"], pub:ca_key["y"], signature:cert["signature"], data:data);
      else if (ca_key["type"] =~ "^ecdsa")
      {
        ca_sig = decode_ecdsa_signature(cert["signature"]);
        if(isnull(ca_sig)) return FALSE;

        return ecdsa_verify(msg       : data,
                            x         : ca_key["q_s_x"],
                            y         : ca_key["q_s_y"],
                            r         : ca_sig["sig_r"],
                            s         : ca_sig["sig_s"],
                            hash      : ca_key["hash_cb"],
                            curve_nid : ca_key["nid"]);
      }

      session.set_error("Unable to verify the certificate signature (CA key type "+ca_key["type"]+" is currently unsupported).");
      return FALSE; # unknown/unsupported CA key type
    }

    ##
    # Decodes/parses an SSH2 public key
    #
    # @anonparam <First> the public key to parse (in binary format)
    # @return a hash of the decoded public key, or
    #         NULL if the operation failed
    # @category SSH
    ##
    function decode_ssh2_public_key()
    {
      local_var key, type;
      key = _FCT_ANON_ARGS[0];
      type = get_ssh_string(buffer:key, pos:0);
      if (type == 'ssh-rsa')
        return decode_ssh2_rsa_public_key(key);
      if (type == 'ssh-dss')
        return decode_ssh2_dsa_public_key(key);
      if (type =~ '^ecdsa')
        return decode_ssh2_ecdsa_public_key(key);

      session.set_error("Unable to parse ssh2 public key: type "+type+" is currently unsupported.");
      return NULL; # unknown/unsupported key type
    }

    ##
    # Decodes/parses an SSH2 DSA public key
    #
    # @anonparam <First> the DSA public key to parse (in binary format)
    # @return a hash of the decoded public key, or
    #         NULL if the operation failed
    # @category SSH
    ##
    function decode_ssh2_dsa_public_key()
    {
      local_var key, ret, pos, tmp;
      key = _FCT_ANON_ARGS[0];
      ret = make_array();
      pos = 0;

      ret["type"] = get_ssh_string(buffer:key, pos:pos);
      pos += 4 + strlen(ret["type"]);

      tmp = get_ssh_mpint(buffer:key, pos:pos);
      ret["p"] = tmp["value"];
      pos += tmp["length"];

      tmp = get_ssh_mpint(buffer:key, pos:pos);
      ret["q"] = tmp["value"];
      pos += tmp["length"];

      tmp = get_ssh_mpint(buffer:key, pos:pos);
      ret["g"] = tmp["value"];
      pos += tmp["length"];

      tmp = get_ssh_mpint(buffer:key, pos:pos);
      ret["y"] = tmp["value"];

      return ret;
    }

    ##
    # Decodes/parses an SSH2 RSA public key
    #
    # @anonparam <First> the RSA public key to parse (in binary format)
    # @return a hash of the decoded public key, or
    #         NULL if the operation failed
    # @category SSH
    ##
    function decode_ssh2_rsa_public_key()
    {
      local_var key, ret, pos, tmp;
      key = _FCT_ANON_ARGS[0];
      ret = make_array();
      pos = 0;
      ret["type"] = get_ssh_string(buffer:key, pos:pos);
      pos += 4 + strlen(ret["type"]);

      tmp = get_ssh_mpint(buffer:key, pos:pos);
      ret["e"] = tmp["value"];
      pos += tmp["length"];

      tmp = get_ssh_mpint(buffer:key, pos:pos);
      ret["n"] = tmp["value"];

      return ret;
    }

    ##
    # Extracts curve type, r and s parameters from a ECDSA signature
    #
    # @anonparam <First> A signature blob.
    # @return Returns a dictionary with the curve type, r and s parameters.
    # @category SSH
    ##
    function decode_ecdsa_signature()
    {
      local_var sig_blob, ret, pos, tmp;
      sig_blob = _FCT_ANON_ARGS[0];
      ret = make_array();
      pos = 0;

      ret["type"] = get_ssh_string(buffer:sig_blob, pos:pos);
      ret["sig_r"] = mk_ssh_mpint('\0');
      ret["sig_s"] = mk_ssh_mpint('\0');

      pos += 4 + strlen(ret["type"]);
      var signature = get_ssh_string(buffer:sig_blob, pos:pos);
      pos = 0;

      tmp = get_ssh_mpint(buffer:signature, pos:pos);
      if(!isnull(tmp))
        ret["sig_r"] = tmp["value"];

      pos += tmp["length"];

      tmp = get_ssh_mpint(buffer:signature, pos:pos);
      if(!isnull(tmp))
        ret["sig_s"] = tmp["value"];

      return ret;
    }

    ##
    # Decodes/parses an SSH2 ECDSA public key
    #
    # @anonparam <First> the ECDSA public key to parse (in binary format)
    # @return Returns a dictionary with the hash algorithm, curve type
    #         and NID of the decoded public key or NULL if there is an error.
    # @category SSH
    ##
    function decode_ssh2_ecdsa_public_key()
    {
      local_var key, ret, pos;
      key = _FCT_ANON_ARGS[0];
      ret = make_array();
      pos = 0;
      ret["type"] = get_ssh_string(buffer:key, pos:pos);
      pos += 4 + strlen(ret["type"]);

      var curve  = get_ssh_string(buffer:key, pos:pos);
      pos += 4 + strlen(curve);

      var q_s  = get_ssh_string(buffer:key, pos:pos);
      if(ret["type"] == "ecdsa-sha2-nistp256")
      {
        ret["nid"] = curve_nid.nist.P256;
        ret["hash_cb"] = @SHA256;
      }
      else if(ret["type"] == "ecdsa-sha2-nistp384")
      {
        ret["nid"] = curve_nid.nist.P384;
        ret["hash_cb"] = @SHA384;
      }
      else if(ret["type"] == "ecdsa-sha2-nistp521")
      {
        ret["nid"] = curve_nid.nist.P521;
        ret["hash_cb"] = @SHA512;
      }

      var curve_info = ecc_curve_details(curve_nid:ret["nid"]);
      if(isnull(curve_info)) return NULL;

      ret["q_s_x"] = substr(q_s, 1, (curve_info.order_bits + 7) / 8);
      ret["q_s_y"] = substr(q_s, 1 + ((curve_info.order_bits + 7) / 8),  ((curve_info.order_bits + 7) / 8) * 2);
      return ret;
    }


    ##
    # Generates data used to verify the signature in an SSH DSA certificate
    #
    # @anonparam <First> the certificate that contains the signature to verify (this should be in the format returned by parse_ssh_cert())
    # @return data used to verify the signature in an SSH DSA certificate
    # @category SSH
    ##
    function generate_ssh_dsa_cert_sig_data()
    {
      local_var cert, data, tmp, tmp_data;
      tmp_data = '';

      cert = _FCT_ANON_ARGS[0];
      if (isnull(cert)) return NULL;

      if (cert["key_type"] == "ssh-dss-cert-v00@openssh.com")
      {
        data =
          mk_ssh_string(cert["key_type"]) +
          mk_ssh_mpint(cert["p"]) +
          mk_ssh_mpint(cert["q"]) +
          mk_ssh_mpint(cert["g"]) +
          mk_ssh_mpint(cert["y"]) +
          cert["type"] +
          mk_ssh_string(cert["key_id"]);

        foreach tmp (cert["valid_principals"])
          tmp_data += mk_ssh_string(tmp);

        data +=
          mk_ssh_string(tmp_data) +
          cert["valid_after"] +
          cert["valid_before"] +
          mk_ssh_string(cert["constraints"]) +
          mk_ssh_string(cert["nonce"]) +
          mk_ssh_string(cert["reserved"]) +
          mk_ssh_string(cert["signature_key"]);
      }
      else
      {
        data =
          mk_ssh_string(cert["key_type"]) +
          mk_ssh_string(cert["nonce"]) +
          mk_ssh_mpint(cert["p"]) +
          mk_ssh_mpint(cert["q"]) +
          mk_ssh_mpint(cert["g"]) +
          mk_ssh_mpint(cert["y"]) +
          cert["serial"] +
          cert["type"] +
          mk_ssh_string(cert["key_id"]);

        foreach tmp (cert["valid_principals"])
          tmp_data += mk_ssh_string(tmp);

        data +=
          mk_ssh_string(tmp_data) +
          cert["valid_after"] +
          cert["valid_before"] +
          mk_ssh_string(cert["critical_options"]) +
          mk_ssh_string(cert["extensions"]) +
          mk_ssh_string(cert["reserved"]) +
          mk_ssh_string(cert["signature_key"]);
      }

      return data;
    }

    ##
    # Generates data used to verify the signature in an SSH ECDSA certificate
    #
    # @anonparam <First> the certificate that contains the signature to verify
    #                    (this should be in the format returned by parse_ssh_cert())
    # @return data used to verify the signature in an SSH ECDSA certificate
    # @category SSH
    ##
    function generate_ssh_ecdsa_cert_sig_data()
    {
      local_var cert, data, tmp, tmp_data;
      tmp_data = '';

      cert = _FCT_ANON_ARGS[0];
      if (isnull(cert)) return NULL;

      data =
        mk_ssh_string(cert["key_type"]) +
        mk_ssh_string(cert["nonce"]) +
        mk_ssh_string(cert["curve"]) +
        mk_ssh_string(cert["public_key"]) +
        cert["serial"] +
        cert["type"] +
        mk_ssh_string(cert["key_id"]);

      foreach tmp (cert["valid_principals"])
        tmp_data += mk_ssh_string(tmp);

      data +=
        mk_ssh_string(tmp_data) +
        cert["valid_after"] +
        cert["valid_before"] +
        mk_ssh_string(cert["critical_options"]) +
        mk_ssh_string(cert["extensions"]) +
        mk_ssh_string(cert["reserved"]) +
        mk_ssh_string(cert["signature_key"]);

      return data;
    }

    ##
    # Validates a DSS server signature
    #
    # @param <p>          The DSS p parameter
    # @param <q>          The DSS g parameter
    # @param <g>          The DSS p parameter
    # @param <pub>        The DSS public key (y parameter)
    # @param <signature>  The digital signature being verified
    # @param <data>       The message that was signed.
    # @return Returns TRUE if the signature is valid, FALSE otherwise.
    # @category SSH
    ##
    function ssh_dss_verify(p, q, g, pub, signature, data)
    {
      local_var sigtype, next, tmp_sig, siglen, r, s, hash;

      sigtype = get_ssh_string(buffer:signature, pos:0);
      if ("ssh-dss" >!< sigtype)
        return 0;

      next = 4 + strlen(sigtype);
      tmp_sig = get_ssh_string(buffer:signature,pos:next);
      siglen = strlen(tmp_sig);

      r = substr(tmp_sig,  0, 19);
      s = substr(tmp_sig, 20, 39);

      hash = SHA1(data);

      return dsa_do_verify(p:p,g:g,q:q,pub:pub,r:r,s:s,data:hash);
    }

    ##
    # Validates a RSA server signature
    #
    # @param <p>          The RSA p parameter
    # @param <q>          The RSA q parameter
    # @param <signature>  The digital signature being verified
    # @param <data>       The message that was signed.
    # @return Returns TRUE if the signature is valid, FALSE otherwise.
    # @category SSH
    ##
    function ssh_rsa_verify(e, n, signature, data)
    {
      local_var hash, sigtype, nlen,
       next, tmp_sig, siglen, len, sig,
       hdecoid, hshaoid, hhash, decrypted, hash_alg;


      local_var fn = 'ssh_rsa_verify';

      local_var id_sha1, id_md5, id_sha256, id_sha384, id_sha512, test_hash;

      # https://www.ietf.org/rfc/rfc3447.txt
      # Page 42 excerpt:
      # 1. For the six hash functions mentioned in Appendix B.1, the DER
      #    encoding T of the DigestInfo value is equal to the following:
      #
      #     MD2:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04
      #                  10 || H.
      #     MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04
      #                  10 || H.
      #     SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
      #     SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
      #                  04 20 || H.
      #     SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00
      #                  04 30 || H.
      #     SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00
      #                     04 40 || H.
      id_sha1   = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14';
      id_md5    = '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10';
      id_sha256 = '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20';
      id_sha384 = '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30';
      id_sha512 = '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40';

      if (!n)
        return 0;
      sigtype = get_ssh_string(buffer:signature, pos:0);

      if(sigtype != "x509v3-ssh-rsa" && sigtype != "x509v3-sign-rsa" && sigtype != "ssh-rsa")
        return 0;

      nlen = strlen(n);
      if (ord(n[0]) == 0)
        nlen--;

      # Used by ssh_key_size.nasl to audit RSA key length
      KEY_LEN = num_bits(n:n);

      # check minimum n size
      if ( (nlen*8) < 512 )
        return 0;

      next = 4 + strlen(sigtype);
      tmp_sig = get_ssh_string(buffer:signature,pos:next);
      siglen = strlen(tmp_sig);

      # bad signature (should be less than n)
      if (siglen > nlen)
        return 0;
      # Add padding if needed
      if (siglen < nlen)
      {
        len = nlen - siglen;
        sig = crap(data:raw_string(0x00), length:len) + tmp_sig;
      }
      else
        sig = tmp_sig;
 
      # must call RSA_public_decrypt from openssl, so convert arg - see ssh-rsa.c
      decrypted = rsa_public_decrypt(sig:sig,e:e,n:n);
      if (!decrypted)
        return 0;

      if(substr(decrypted, 0, strlen(id_md5) - 1) == id_md5)
      {
        hash = MD5(data);
        test_hash = substr(decrypted,strlen(id_md5));

        if(strlen(hash) != 16 || strlen(test_hash) != 16)
          return 0;
      }
      else if(substr(decrypted, 0, strlen(id_sha1) - 1) == id_sha1)
      {
        hash = SHA1(data);
        test_hash = substr(decrypted,strlen(id_sha1));

        if(strlen(hash) != 20 || strlen(test_hash) != 20)
          return 0;
      }
      else if(substr(decrypted, 0, strlen(id_sha256) - 1) == id_sha256)
      {
        if(!defined_func("SHA256")) return 0;
        hash = SHA256(data);
        test_hash = substr(decrypted,strlen(id_sha256));

        if(strlen(hash) != 32 || strlen(test_hash) != 32)
          return 0;
      }
      else if(substr(decrypted, 0, strlen(id_sha384) - 1) == id_sha384)
      {
        if(!defined_func("SHA384")) return 0;
        hash = SHA384(data);
        test_hash = substr(decrypted,strlen(id_sha384));

        if(strlen(hash) != 48 || strlen(test_hash) != 48)
          return 0;
      }
      else if(substr(decrypted, 0, strlen(id_sha512) - 1) == id_sha512)
      {
        if(!defined_func("SHA512")) return 0;
        hash = SHA512(data);
        test_hash = substr(decrypted,strlen(id_sha512));

        if(strlen(hash) != 64 || strlen(test_hash) != 64)
          return 0;
      }
      else return 0;

      hdecoid = hexstr(test_hash);
      hhash = hexstr(hash);

      if (hdecoid != hhash)
        return 0;

      return 1;
    }

    ##
    # Parses the parts of a digital signature common to all supported algorithms
    #
    # @param <cert>      An SSH digital certificate
    # @param <cert_info> A dictionary storing parsed certificate parameters
    # @param <pos:int>   Position within the certificate that common parameters start
    # @return Returns the cert_info function argument with common parameters added to it,
    #         or NULL if an error occurs.
    # @category SSH
    ##
    function parse_ssh_end_of_cert(cert, cert_info, pos)
    {
      local_var tmp, tmp_pos, tmp_list;
      var ret = cert_info;
      if (ret["key_type"] !~ "^.*-cert-v00@openssh.com")
      {
        ret["serial"] = substr(cert, pos, pos + 7);
        pos += 8;
      }

      ret["type"] = substr(cert, pos, pos + 3);
      pos += 4;

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["key_id"] = tmp;
      pos += 4 + strlen(ret["key_id"]);

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["valid_principals"] = tmp;
      pos += 4 + strlen(ret["valid_principals"]);

      tmp_pos = 0;
      tmp_list = make_list();
      while(tmp_pos < strlen(ret["valid_principals"]))
      {
        tmp = get_ssh_string(buffer:ret["valid_principals"], pos:tmp_pos);
        tmp_list = make_list(tmp_list, tmp);
        tmp_pos += 4 + strlen(tmp);
      }
      ret["valid_principals"] = tmp_list;

      ret["valid_after"] = substr(cert, pos, pos + 7);
      pos += 8;

      ret["valid_before"] = substr(cert, pos, pos + 7);
      pos += 8;

      if (ret["key_type"] =~ "^.*-cert-v00@openssh.com")
      {
        tmp = get_ssh_string(buffer:cert, pos:pos);
        if(isnull(tmp)) return NULL;
        ret["constraints"] = tmp;
        pos += 4 + strlen(ret["constraints"]);

        tmp = get_ssh_string(buffer:cert, pos:pos);
        if(isnull(tmp)) return NULL;
        ret["nonce"] = tmp;
        pos += 4 + strlen(ret["nonce"]);
      }
      else
      {
        tmp = get_ssh_string(buffer:cert, pos:pos);
        if(isnull(tmp)) return NULL;
        ret["critical_options"] = tmp;
        pos += 4 + strlen(ret["critical_options"]);

        tmp = get_ssh_string(buffer:cert, pos:pos);
        if(isnull(tmp)) return NULL;
        ret["extensions"] = tmp;
        pos += 4 + strlen(ret["extensions"]);
      }

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["reserved"] = tmp;
      pos += 4 + strlen(ret["reserved"]);

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["signature_key"] = tmp;

      tmp = get_ssh_string(buffer:ret["signature_key"], pos:0);
      if(isnull(tmp)) return NULL;
      ret["signature_type"] = tmp;
      pos += 4 + strlen(ret["signature_key"]);

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["signature"] = tmp;
      pos += 4 + strlen(ret["signature"]);

      return ret;
    }

    ##
    # Parses a SSH DSA digital signature
    #
    # @param <cert>      An SSH digital certificate
    # @return Returns a dictionary containing parameters parsed from the certificate,
    #         or NULL if an error occurs.
    # @category SSH
    ##
    function parse_ssh_dsa_cert(cert)
    {
      local_var ret, pos, tmp, tmp_pos, tmp_list, fn;
      fn = 'parse_ssh_dsa_cert';
      ret = make_array();
      pos = 0;

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["key_type"] = tmp;

      pos += 4 + strlen(ret["key_type"]);

      if (ret["key_type"] != "ssh-dss-cert-v00@openssh.com")
      {
        tmp = get_ssh_string(buffer:cert, pos:pos);
        if(isnull(tmp)) return NULL;
        ret["nonce"] = tmp;
        pos += 4 + strlen(ret["nonce"]);
      }

      tmp = get_ssh_mpint(buffer:cert, pos:pos);
      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return NULL;
      ret["p"] = tmp['value'];
      pos += tmp['length'];

      tmp = get_ssh_mpint(buffer:cert, pos:pos);
      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return NULL;
      ret["q"] = tmp['value'];
      pos += tmp['length'];

      tmp = get_ssh_mpint(buffer:cert, pos:pos);
      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return NULL;
      ret["g"] = tmp['value'];
      pos += tmp['length'];

      tmp = get_ssh_mpint(buffer:cert, pos:pos);
      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return NULL;
      ret["y"] = tmp['value'];
      pos += tmp['length'];

      return parse_ssh_end_of_cert(cert:cert, cert_info:ret, pos:pos);
    }

    ##
    # Parses a SSH RSA digital signature
    #
    # @param <cert>      An SSH digital certificate
    # @return Returns a dictionary containing parameters parsed from the certificate,
    #         or NULL if an error occurs.
    # @category SSH
    ##
    function parse_ssh_rsa_cert(cert)
    {
      local_var ret, pos, tmp, tmp_pos, tmp_list, fn;
      fn = 'parse_ssh_rsa_cert';
      ret = make_array();
      pos = 0;

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;

      ret["key_type"] = tmp;

      pos += 4 + strlen(ret["key_type"]);

      if (ret["key_type"] != "ssh-rsa-cert-v00@openssh.com")
      {
        tmp = get_ssh_string(buffer:cert, pos:pos);
        if(isnull(tmp)) return NULL;
        ret["nonce"] = tmp;
        pos += 4 + strlen(ret["nonce"]);
      }

      tmp = get_ssh_mpint(buffer:cert, pos:pos);
      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return NULL;
      ret["e"] = tmp['value'];
      pos += tmp['length'];

      tmp = get_ssh_mpint(buffer:cert, pos:pos);
      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return NULL;
      ret["n"] = tmp['value'];
      pos += tmp['length'];

      return parse_ssh_end_of_cert(cert:cert, cert_info:ret, pos:pos);
    }

    ##
    # Parses a SSH ECDSA digital signature
    #
    # @param <cert>      An SSH digital certificate
    # @return Returns a dictionary containing parameters parsed from the certificate,
    #         or NULL if an error occurs.
    # @category SSH
    ##
    function parse_ssh_ecdsa_cert(cert)
    {
      local_var ret, pos, tmp, tmp_pos, tmp_list, fn;
      fn = 'parse_ssh_ecdsa_cert';
      ret = make_array();
      pos = 0;

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["key_type"] = tmp;
      pos += 4 + strlen(tmp);

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["nonce"] = tmp;
      pos += 4 + strlen(tmp);

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["curve"] = tmp;
      pos += 4 + strlen(tmp);

      tmp = get_ssh_string(buffer:cert, pos:pos);
      if(isnull(tmp)) return NULL;
      ret["public_key"] = tmp;
      pos += 4 + strlen(tmp);

      return parse_ssh_end_of_cert(cert:cert, cert_info:ret, pos:pos);
    }

    ##
    # Parses a SSH digital signature
    #
    # @param <cert>      An SSH digital certificate
    # @return Returns a dictionary containing parameters parsed from the certificate,
    #         or NULL if an error occurs.
    # @category SSH
    ##
    public function parse_ssh_cert(cert)
    {
      local_var type;
      type = get_ssh_string(buffer:cert, pos:0);
      if ('ssh-rsa-cert' >< type)
        return parse_ssh_rsa_cert(cert:cert);
      else if ('ssh-dss-cert' >< type)
        return parse_ssh_dsa_cert(cert:cert);
      else if(type =~ "^ecdsa-sha2-nistp" && "-cert-" >< type)
        return parse_ssh_ecdsa_cert(cert:cert);
      return NULL; # error condition
    }

    ##
    # Verifies the provided host key or host certificate against hosts known by this GizaNE
    #
    # @param <key>             An SSH host key
    # @param <key_type:string> Describes the keying algorithm
    # @param <cert>            An SSH host certificate
    # @return Returns TRUE if a matching key is found, FALSE otherwise
    # @category SSH
    ##
    public function verify_known_hosts(key, key_type, cert)
    {
      local_var ca_key, ca_keys, hostname, host_ip, host_string, known_key, ca_match, principal, revoked_key, valid_principal;
      local_var val_key_count, validated_keys, fn = obj + '.verify_known_hosts';

      session.dbg_log(fn:fn, level:DEBUG3, message:"Verifying the host key / certificate against the SSH known_hosts file provided in the scan policy...");

      # If the server provided a host certificate, extract its public key
      if(cert)
      {
        key = get_pub_key_from_cert(cert);
        if (cert["key_type"] =~ "^ssh-rsa-")
          key_type = "rsa";
        else if (cert["key_type"] =~ "^ssh-dss-")
          key_type = "dss";
      }

      # Check to see if we already have a validated key stored in the kb
      local_var kt, kbname;
      if (key_type !~ "^ecdsa")
        kt = 'ssh-'+key_type;
      else
        kt = key_type;

      kbname = SSH_LIB_KB_PREFIX+session.get_kb_connection_id()+'/hostkey/validated/'+kt;
      validated_keys = get_kb_blob_list(kbname);

      local_var vk;
      foreach (vk in validated_keys)
      {
        if (vk == key)
        {
          session.dbg_log(fn:fn, level:DEBUG3, message:'Found matching, validated key in kb.\n',
              base64:key);
          return TRUE;
        }
      }
      session.dbg_log(fn:fn, level:DEBUG3, message:'No validated key found in kb. Proceeding with validation.\n');

      # Set host string of hostname/IP for debugging
      hostname = get_host_name();
      host_ip = get_host_ip();
      host_string = hostname;
      if(hostname != host_ip)
        host_string += ', ' + host_ip;

      # If neither of these KB items are present, a known_hosts file was not
      # provided in the scan policy
      ca_keys = get_kb_list("SSH/CAKey");
      known_key = get_kb_item("SSH/KnownFingerprint/" + kt);
      if(isnull(ca_keys) && isnull(known_key))
      {
        session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: A known_hosts file was not provided in the scan policy or the known_hosts file provided did not contain any entries matching this host: " + host_string);
        return TRUE;
      }

      # If the remote SSH server only provided a host key, not a host
      # certificate, and a known host key was not provided in the same
      # key type, the host cannot be validated
      if (!cert && !known_key)
        return session.set_error("The host's "+key_type+" public key is missing from the scan policy's SSH known_hosts file. A CA key may have been provided to validate a remote SSH server certificate for this host, but the remote SSH server did not send a certificate.");

      # Check if the key has been revoked
      foreach revoked_key (get_kb_list("SSH/RevokedKey"))
      {
        # Check if the host key itself has been revoked
        if (base64(str:key) == revoked_key)
        {
          return session.set_error("The host's "+key_type+" public key has been revoked in the scan policy's SSH known_hosts file.");
        }

        # If a host certificate was provided, check if the key of the CA
        # used to sign the certificate has been revoked
        if (cert && base64(str:cert["signature_key"]) == revoked_key)
        {
          return session.set_error("The public key of the CA used to sign this host's "+cert["key_type"]+" certificate has been revoked in the scan policy's SSH known_hosts file.");
        }
      }

      # If a certificate was provided, check if the key was signed by a
      # trusted CA and includes the host as a valid principal
      if (cert && !isnull(ca_keys))
      {
        ca_match = FALSE;
        valid_principal = FALSE;
        foreach ca_key (ca_keys)
        {
          if (base64(str:cert["signature_key"]) == ca_key)
          {
            session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH server certificate was signed using a trusted CA key listed in the scan policy's SSH known_hosts file.");
            ca_match = TRUE;
            break;
          }
        }

        # If we found a matching CA, verify that the principal is valid
        if(ca_match)
        {
          # As a special case, a zero-length "valid principals" field
          # means the certificate is valid for any principal of the
          # specified type.
          # Ref: http://www.openssh.com/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.9
          if (max_index(cert["valid_principals"]) == 0)
          {
            session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH server certificate is valid for any principal because the valid principals field is zero-length.");
            valid_principal = TRUE;
          }

          # Otherwise, check to see if either the hostname or host IP
          # is listed as a valid principal for the certificate
          else
          {
            session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The following principals (hostnames) were found in the server certificate: " + serialize(cert["valid_principals"]));
            foreach principal (cert["valid_principals"])
            {
              if (principal == hostname || principal == host_ip)
              {
                session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH server certificate includes the SSH server host in its list of valid principals.");
                valid_principal = TRUE;
                break;
              }
            }
          }

          # If we found a matching CA and the principal is valid, we've
          # validated the remote host
          if(valid_principal)
          {
            session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH certificate was validated: It is signed by a trusted CA and includes the target host as a valid principal.");
            # store the validated key in the kb
            set_kb_blob(name:kbname, value:key);
            return TRUE;
          }
          # If the CA is valid but the principal is invalid, we will still
          # check for a valid host key, so just log and continue
          else session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH server's certificate does not contain the following principal(s) : " + host_string);
        }

        # If we didn't find a matching CA, we will still check to see if
        # the server's individual key is trusted, so just log and continue
        else session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH server certificate was not signed by any of the trusted CAs with patterns matching the hostname " + host_string + " in the scan policy's SSH known_hosts file.");
      }
      else if (cert && isnull(ca_keys))
        session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH server provided a certificate but there was not a CA key provided in the known_hosts file with a pattern to match this hostname: " + host_string);
      # end certificate checks

      # Check if the host's key is explicitly listed as trusted
      if (known_key)
      {
        if(base64(str:key) == known_key)
        {
          # store the validated key in the kb
          set_kb_blob(name:kbname, value:key);
          session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: The SSH certificate was validated: The SSH server's "+key_type+" public key matches the fingerprint in the scan policy's SSH known_hosts file.");
          return TRUE;
        }

        known_key = base64_decode(str:known_key);

        if ("@NOTSET@" >< known_key)
          return session.set_error("The host's "+key_type+" public key is missing from the scan policy's SSH known_hosts file.");

        return session.set_error("The host's "+key_type+" public key does not match the fingerprint in the scan policy's SSH known_hosts file.");
      }
      else
      {
        session.dbg_log(fn:fn, level:DEBUG3, message:"kex_handler: Public keys matching hostname " + host_string + " were not provided in the scan policy's known_hosts file, only trusted CA keys were provided to match this hostname.");
      }

      # If we got this far, that means trusted CA keys were supplied for
      # this host in known_hosts but a public key for the key type was not,
      # AND the server's certificate either was not signed by any of the
      # trusted CAs or did not include a principal (hostname) that matched
      # the remote host
      if(!ca_match)
        return session.set_error("The SSH server's certificate was not signed by any of the trusted CAs in the scan policy's SSH known_hosts file and the host's "+key_type+" public key was not provided in the scan policy's SSH known_hosts file.");
      else
        return session.set_error("The SSH server's certificate was signed by a trusted CA in the scan policy's SSH known_hosts file, but the certificate does not contain the principal(s) '"+host_string+"' and the host's "+key_type+" public key was not provided in the scan policy's SSH known_hosts file.");
    }

    ##
    # Extracts the public key from an SSH certificate
    #
    # @anonparam <First> An SSH certificate
    # @return Returns the certificate's public key
    # @category SSH
    ##
    public function get_pub_key_from_cert()
    {
      local_var cert, key;
      cert = _FCT_ANON_ARGS[0];
      key = NULL;

      if (cert["key_type"] =~ "^ssh-rsa-")
        key = encode_ssh_rsa_public_key(e:cert["e"], n:cert["n"]);
      else if (cert["key_type"] =~ "^ssh-dss-")
        key = encode_ssh_dsa_public_key(p:cert["p"], q:cert["q"], g:cert["g"], y:cert["y"]);
      else if (cert["key_type"] =~ "^ecdsa-")
        key = encode_ecdsa_public_key(type:cert["key_type"], curve:cert["curve"], pk:cert["public_key"]);
      else
        session.set_error("Unable to get public key from certificate. Unknown or unsupported key type.");

      return key;
    }

    ##
    # Encodes an SSH RSA public key from e and n parameters
    #
    # @param <e> An RSA e parameter
    # @param <n> An RSA n parameter
    # @return Returns an encoded public key
    # @category SSH
    ##
    function encode_ssh_rsa_public_key(e, n)
    {
      local_var key;
      key =
        mk_ssh_string('ssh-rsa') +
        mk_ssh_mpint(e) +
        mk_ssh_mpint(n);
      return key;
    }

    ##
    # Encodes an SSH DSA public key from e and n parameters
    #
    # @param <p> An DSA p parameter
    # @param <q> An DSA q parameter
    # @param <g> An DSA g parameter
    # @param <y> An DSA y parameter
    # @return Returns an encoded public key
    # @category SSH
    ##
    function encode_ssh_dsa_public_key(p, q, g, y)
    {
      local_var key;
      key = 
        mk_ssh_string('ssh-dss') +
        mk_ssh_mpint(p) +
        mk_ssh_mpint(q) +
        mk_ssh_mpint(g) +
        mk_ssh_mpint(y);
      return key;
    }

    ##
    # Encodes an SSH ECDSA public key from key and type
    #
    # @param <type:string>  An ECDSA curve name
    # @param <curve:int>    OpenSSL curve NID
    # @param <pk>           Public key bytes
    # @return Returns an encoded public key
    # @category SSH
    ##
    function encode_ecdsa_public_key(type, curve, pk)
    {
      var key =
        mk_ssh_string(type) +
        mk_ssh_string(curve) +
        mk_ssh_string(pk);
      return key;
    }

    ##
    # Sets a private field in this kex_handler object in support of unit testing
    #
    # @param <field:string> A kex_handler member variable
    # @param <value>        A value to set
    # @return Returns NULL
    ##
    public function set_private_field(field, value)
    {
      if (field >!< serialize(keys(this)))
      {
        this.session.dbg_log(fn:'set_private_field',
            level:DEBUG1,
            message:field+' is not a field of kex_handler');
        return NULL;
      }
      this[field] = value;
    }

    ##
    # Tests a private member function of this kex_handler object
    #
    # @param <name:string> A kex_handler member function name
    # @param <kwargs>      A dictionary of function arguments to use
    # @param <args>        An array of argument values to use
    # @return Returns the result of invoking the named private function with the
    #         parameters provided.
    ##
    public function test_private_function(name, kwargs, args)
    {
      var fn = obj+'.test_private_function';
      if (isnull(name))
      {
        this.session.dbg_log(fn:fn, level:DEBUG1,
            message:'missing name parameter');
        return NULL;
      }
      switch (name)
      {
        case "generate_ssh_rsa_cert_sig_data":
          return generate_ssh_rsa_cert_sig_data(args[0]);
        case "generate_ssh_dsa_cert_sig_data":
          return generate_ssh_dsa_cert_sig_data(args[0]);
        case "generate_ssh_ecdsa_cert_sig_data":
          return generate_ssh_ecdsa_cert_sig_data(args[0]);
        case "decode_ssh2_public_key":
          return decode_ssh2_public_key(args[0]);
        case "dh_valid_key":
          return dh_valid_key(key:kwargs['key'],
                              p:kwargs['p']);
        case "ssh_derive_keys":
          return ssh_derive_keys(hash:kwargs['hash'],
                                 session_id:kwargs['session_id'],
                                 shared:kwargs['shared'],
                                 hash_type:kwargs['hash_type'],
                                 max:kwargs['max']);
        case "mk_ssh_mpint":
          return mk_ssh_mpint(buffer:kwargs['buffer']);
        case "ssh_rsa_verify":
          return ssh_rsa_verify(e:kwargs.e,
                                n:kwargs.n,
                                signature:kwargs.signature,
                                data:kwargs.data);
        default:
          this.session.dbg_log(fn:fn, level:DEBUG1,
              message:name+' is not yet implemented for testing with this function');
          return NULL;
      }
    }
  }

  ##
  # Generates a cryptographic signature of an SSH message using an ECDSA key
  #
  # @param <priv>    An ECDSA private key
  # @param <nid:int> OpenSSL curve NID
  # @param <digest>  The hash digest of an SSH message to sign
  # @return Returns the computed signature as r and s curve parameters or NULL if an error occurs.
  # @remark SEC 1: Elliptic Curve Cryptography, Version 2.0 (http://www.secg.org/sec1-v2.pdf) Ch. 4.3.5
  # @category SSH
  ##
  function ecdsa_sign(priv, nid, digest)
  {
    local_var r, s, k, e, bits_to_drop;
    s = bn_dec2raw("0");

    var curve_info = ecc_curve_details(curve_nid:nid);
    if(isnull(curve_info)) return NULL;

    # Truncate digest if the hash is bigger than the curve
    bits_to_drop = (strlen(digest) * 8) - curve_info.order_bits;
    if (bits_to_drop > 0)
      e = bn_rshift(bn:digest, bits:bits_to_drop);
    else
      e = digest;

    var scount = 0;
    # bn_cmp against bn_dec2raw("0") will not report -1 for big numbers with their MSB set
    while ((bn_cmp(key1:s, key2:bn_dec2raw("0")) == 0 || s[0] >= '\x80') && scount < 1024)
    {
      var rcount = 0;
      r = bn_dec2raw("0");
      while ((bn_cmp(key1:r, key2:bn_dec2raw("0")) == 0 || r[0] >= '\x80') && rcount < 1024)
      {
        k = ecc_generate_secret_key(curve_nid: nid);
        var k_x_y = ecc_scalar_multiply(scalar:k, curve_nid:nid);
        r = bn_mod(k_x_y.x, curve_info.order);

        rcount += 1;
      }
      var factor = bn_mod_mul(r, priv, curve_info.order);
      factor = bn_mod_add(e, factor, curve_info.order);

      var inv_k = bn_mod_inverse(k, curve_info.order);
      s = bn_mod_mul(inv_k, factor, curve_info.order);

      scount += 1;
    }
    return mk_ssh_string(r) + mk_ssh_string(s);
  }

  ##
  # Takes a passphrase and extends it into a decryption key
  #
  # @param <passphrase> A passphrase
  # @param <iv>         The initial vector
  # @param <keysize>    The number of bytes in the key
  # @return Returns the decryption key
  # @remark An implementation of PBKDF1 from section 5.1 of IETF RFC 2898
  #         https://www.ietf.org/rfc/rfc2898.txt
  # @category SSH
  ##
  function make_key_from_passphrase(passphrase, iv, keysize)
  {
     local_var size;

     var salt = iv;
     if (strlen(salt) > 8) salt = substr(iv, 0, 7);

     var bytes_left = keysize;
     var digest = '';
     var to_hash = '';
     var key = '';

     while(bytes_left > 0)
     {
       if (strlen(digest) > 0)
         to_hash = digest;
       else
         to_hash = '';

       to_hash += passphrase;
       to_hash += salt;
       digest = MD5(to_hash);
       size = len(digest);
       if (bytes_left < len(digest))
       {
         key += substr(digest, 0, bytes_left - 1);
         size = bytes_left;
       }
       else
         key += digest;

       bytes_left -= size;
     }

     return key;
  }


  ##
  # Decrypts a passphrase protected SSH key
  #
  # @param <encoded_key>        The key to decrypt
  # @param <iv>                 The initial vector
  # @param <cipher:string>      The cipher used to encrypt the key
  # @param <passphrase:string>  The passphrase for decrypting the key
  # @param <session>            The SSH session - for reporting errors
  # @return Returns the decrypted key or NULL if an error occurs.
  # @category SSH
  ##
  function decrypt_protected_priv_key(encoded_key, iv, cipher, passphrase, session)
  {
    if (empty_or_null(iv) || empty_or_null(cipher) || empty_or_null(encoded_key))
      return NULL;

    # Map the openssh cipher to our cipher names - the assumption here with these
    # rather loose mappings is that if use the wrong cipher the PK won't be decrypted
    # correctly and an unsupported key error will be reported.
    var orig_cipher = cipher;
    cipher = tolower(cipher);

    if (cipher =~ '^aes')
      cipher = ereg_replace(pattern: "^aes-(.*)$", string: cipher, replace: "aes\1");
    else if (cipher == 'des-ede3-cbc' || cipher == 'des3')
      cipher = "3des-cbc";
    else if (cipher == 'blowfish' || cipher == 'bf' || cipher == 'bf-cbc')
      cipher = "blowfish-cbc";
    else
    {
      if(!isnull(session))
        return session.set_error("Passphrase protected private key encrypted with unsupported cipher type: " + orig_cipher);
      else
        return NULL;
    }

    var cipherset = new("sshlib::cipherset");

    cipherset.set_crypto_alg(cipher, sshlib::MODE_IN);
    var key_len = cipherset.get_key_length(mode: sshlib::MODE_IN);
    if(key_len <= 0)
    {
      if(!isnull(session))
        return session.set_error("Unable to decrypt passphrase protected private key. Unsupported cipher type: " + orig_cipher);
      else
        return NULL;
    }

    var key = make_key_from_passphrase(passphrase:passphrase, iv: iv, keysize: key_len);

    var enckeys = make_list();
    enckeys[0] = crap(data:'\0', length:strlen(iv));
    enckeys[1] = iv;
    enckeys[2] = crap(data:'\0', length:strlen(key));
    enckeys[3] = key;
    enckeys[4] = crap(data:'\0', length:strlen(iv));
    enckeys[5] = crap(data:'\0', length:strlen(key));

    cipherset.set_enc_keys(enckeys);

    return cipherset.decrypt(data:encoded_key);
  }

  ##
  # Converts a PEM encoded SSH key into its ECDSA binary form
  #
  # @param <priv>              A PEM encoded private key
  # @param <passphrase:string> A passphrase - required to unlock protected keys
  # @param <session>           The SSH session - for reporting errors
  # @return Returns the binary key as a dictionary of parameters or NULL if an error occurs.
  # @category SSH
  ##
  function pem_to_ecdsa(priv, passphrase, session)
  {
    local_var i, line, matches, der_key;

    # There is no key
    if(isnull(priv)) return NULL;
    var lines = split(chomp(priv), sep:'\n', keep:FALSE);

    if( max_index(lines) < 2) return NULL;
    if( "--BEGIN EC PRIVATE KEY" >!< lines[0] || "--END EC PRIVATE KEY" >!< lines[max_index(lines)-1])  return NULL;

    var encoded_key = '';
    var encrypted = FALSE;
    var pk_cipher = '';
    var iv = '';

    for (i=1; i < max_index(lines)-1; i++)
    {
      line = chomp(lines[i]);
      if (line =~ '^Proc-Type:.*ENCRYPTED')
      {
        encrypted = TRUE;
        continue;
      }

      matches = pregmatch(pattern:"^DEK-Info: ([\w-]+),(\w+)", string: line);
      if (!empty_or_null(matches))
      {
        pk_cipher = matches[1];
        iv = hex2raw(s:matches[2]);
        continue;
      }

      if(strlen(line) > 0)
        encoded_key += line;
    }

    der_key = base64_decode(str: encoded_key);
    if (encrypted)
    {
      if (empty_or_null(iv) || empty_or_null(pk_cipher) || empty_or_null(encoded_key))
        return NULL;

      der_key = decrypt_protected_priv_key(encoded_key: der_key,
                                           iv: iv,
                                           cipher: pk_cipher,
                                           passphrase: passphrase,
                                           session: session);
    }

    if(empty_or_null(der_key)) return NULL;

    var asn1_key = der_decode(data:der_key);
    if(empty_or_null(asn1_key)) return NULL;

    asn1_key = asn1_key[1];
    var pos = 0;
    var length_der = der_decode(data:asn1_key, pos:0);

    #Check the der code here to detect bad private key decryption or user submitted garbage.
    if(empty_or_null(length_der) || length_der[0] != 2) return NULL;
    pos = length_der[2];
    var der_private_key = der_decode(data:asn1_key, pos:pos);

    if(empty_or_null(der_private_key)) return NULL;
    pos = der_private_key[2];
    var parameters = der_decode(data:asn1_key, pos:pos);

    if(empty_or_null(parameters)) return NULL;
    pos = parameters[2];
    var asn_public_key = der_decode(data:asn1_key, pos:pos);
    if(empty_or_null(asn_public_key)) return NULL;


    var der_public_key = der_decode(data:asn_public_key[1]);
    if(empty_or_null(der_public_key)) return NULL;

    var key = {};
    key.priv = der_private_key[1];

    var der_named_curve = der_decode(data:parameters[1], pos:0);
    if(empty_or_null(der_named_curve)) return NULL;

    var named_curve = der_decode_oid(oid: der_named_curve[1]);
    key.nid = curve_nid.oid[named_curve];

    var nidname;
    if(key.nid == curve_nid.nist.P256)
      nidname = "nistp256";
    else if(key.nid == curve_nid.nist.P384)
      nidname = "nistp384";
    else if(key.nid == curve_nid.nist.P521)
      nidname = "nistp521";
    else
      return NULL;

    key.type = "ecdsa-sha2-" + nidname;
    key.alg = key.type;
    var pk_point = substr(der_public_key[1], 1);
    key.pub = mk_ssh_string(key.type) + mk_ssh_string(nidname) + mk_ssh_string(pk_point);

    return key;
  }
}
