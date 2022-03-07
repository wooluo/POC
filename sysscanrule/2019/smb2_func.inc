#TRUSTED 6485ae04ca3894ac6dadaebe9f0d9878f423bddac2e6eea6d7c4b8207b35de44409fb7f7491b604808be519d23a1be18d9955c2c7db0dc2c1553ed24788d6b561cc6cd87fdd128717c630ff84ff9c2efa149a7545e70ec4afa71ef559e3cbf3dca43a6ad850787f195abea891f3eef2a72aff079527c66925d3755c9a5cecd2abb70601a1e34e840a627ac793a125661d063cb93e307780ba38640d091150a430473d2e98ac15596a6c05bf923a33af51a969f0623d4f45abe53c51b374e320e507772650340ec0fb8907098fd126e733b19f5d94e646fb7bb684457e443d8103c063f07e15ac6b0544cc58078897b26ff7580262013d7c3eb5871c9703f16b3b72f501e9a1f13d723043d6e9a813a36a61587d2e155cc217bf542db8ba7be20593c008fdbcf695a5a544f9718292c74ddc89097b45c4eee007f90d57954f4a43a9b8b61f9a6751886dbfe010a2b73c18273bcaa06ded6dc2493b2017826f72fba92097bc9cc1b77426734416d5b65177c62b5f9ef77e8670ff229810e64eb3b028f4f351a42f4533d5bc16dc002a436fb495451a68c780f548ff260a2beaf9d140accfdf786194de57583cd73996706db4d97ab97ed38a3d4ee5c0812f8d169987ff19d233a6b94ebad5259118b6d4e5de83dba225a659ed66fcee5047105f0c65ae903403440f3339b81b0c7ebc4dd192d6ee1d7bc1ca1af2b299ccac07fbc
#------------------------------------------------------------------------------
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# smb2_func.inc
# Revision: 1.34
#

global_var sha_k, null_signature;

null_signature = crap(data:'\0', length:16);

# Leave room for the smb2 header
SMB2_MAX_OUTPUT_RESPONSE = 0xFFFF - 110;

SMB2_FLAGS_SIGNED     = 8;

SMB2_0_IOCTL_IS_FSCTL  = 1;

FSCTL_PIPE_TRANSCEIVE  = 0x0011C017;

SMB2_RESTART_SCANS       = 0x01;
SMB2_RETURN_SINGLE_ENTRY = 0x02;
SMB2_INDEX_SPECIFIED     = 0x04;
SMB2_REOPEN              = 0x10;

SMB2_0_INFO_FILE         = 0x01;
SMB2_0_INFO_FILESYSTEM   = 0x02;
SMB2_0_INFO_SECURITY     = 0x03;
SMB2_0_INFO_QUOTA        = 0x04;

#==================================================================#
# Section 1. Crypto                                                #
#==================================================================#

sha_k = make_list(
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

#==================================================================#
# Section 2. Utilities                                             #
#==================================================================#

#---------------------------------------------------------#
# Function    : mklist                                    #
# Description : Generates a list                          #
#---------------------------------------------------------#

function mklist()
{
 local_var ret;
 local_var i, l;

 l = max_index (_FCT_ANON_ARGS);

 if ( defined_func("fill_list") )
  ret  = fill_list(length:l, value:0);

 for (i=0 ; i<l ; i++)
   ret[i] = _FCT_ANON_ARGS[i];

 return ret;
}


#---------------------------------------------------------#
# Function    : raw_qword                                 #
# Description : Converts a DWORD to a raw little endian   #
#               QWORD                                     #
#---------------------------------------------------------#

function raw_qword(q)
{
  return raw_dword(d:q) + raw_dword(d:0);
}

#---------------------------------------------------------#
# Function    : get_qword                                 #
# Description : Reads a QWORD in a buffer and converts it #
#               to a DWORD                                #
#---------------------------------------------------------#

function get_qword(blob, pos)
{
  return get_dword(blob:blob, pos:pos);
}

#==================================================================#
# Section 3. SMB2 Code                                             #
#==================================================================#

#---------------------------------------------------------#
# Function    : smb2_header                               #
# Description : Returns an encoded SMB header without     #
#               the signature                             #
#---------------------------------------------------------#

function smb2_header(command, status, flags)
{
  local_var header, fl;

  if (isnull(flags))
    flags = 0;

  header = '\xFESMB'                             + # ProtocolId
           raw_word(w:64)                        + # StructureSize
           raw_word(w:0)                         + # Credit Charge
           raw_dword(d:status)                   + # Status
           raw_word(w:command)                   + # Command
           raw_word(w:126)                       + # Credits
           raw_dword(d:flags)                    + # Flags
           raw_dword(d:0)                        + # NextCommand
           raw_qword(q:session_get_messageid())  + # MessageId
           raw_dword(d:session_get_pid())        + # ProcessId
           raw_dword(d:session_get_tid())        + # TreeId
           session_get_sid();                      # SessionId

  return header;
}

#---------------------------------------------------------#
# Function    : smb2_decode_header                        #
# Description : Decodes a SMB2 header                     #
#---------------------------------------------------------#

function smb2_decode_header(header)
{
  local_var ret;

  if (strlen(header) != 64)
    return NULL;

  ret = NULL;

  ret[0]  = substr( header, 0, 3);           # ProtocolId (\xFESMB)
  ret[1]  = get_word(  blob:header, pos:4);  # Header Length
  ret[2]  = get_word(  blob:header, pos:6);  # Credit Charge
  ret[3]  = get_dword( blob:header, pos:8);  # Status
  ret[4]  = get_word(  blob:header, pos:12); # Command
  ret[5]  = get_word(  blob:header, pos:14); # Credits Granted
  ret[6]  = get_word(  blob:header, pos:16); # Flags
  ret[7]  = get_word(  blob:header, pos:20); # Next Command Offset
  ret[8]  = get_qword( blob:header, pos:24); # Message ID
  ret[9]  = get_dword( blob:header, pos:32); # Process ID
  ret[10] = get_dword( blob:header, pos:36); # Tree ID
  ret[11] = substr( header, 40, 47);         # Session ID
  ret[12] = substr( header, 48, 63);         # Signature

  return ret;
}

#---------------------------------------------------------#
# Function    : decode_smb2                               #
# Description : Decodes a SMB2 packet                     #
#---------------------------------------------------------#

function decode_smb2(data)
{
  local_var header, length, plaintext;
  local_var key, tohash, hash, command, dialect, status, messageid;


  # Check if the packet is an smbv3 encrypted packet
  if (session_get_encrypt_msgs())
  {
    plaintext = smb3_decrypt_packet(packet:data);
    if (!isnull(plaintext))
      data = plaintext;
  }

  length = strlen(data);
  if (length < 64)
    return NULL;

  header = smb2_decode_header(header:substr(data, 0, 63));
  status = header[3];
  command = header[4];

  # Set next message id from server's response
  messageid = header[8];
  session_set_messageid(id:messageid+1);

  dialect = session_get_dialect();


  if ((dialect == NULL || dialect >= 0x300) && (command == SMB2_NEGOTIATE || (command == SMB2_SESSION_SETUP && status != STATUS_SUCCESS)))
    smb3_update_preintegrity_hashval(data:substr(data, 0, 47) + null_signature + substr(data, 64, length-1));

  if (length > 64)
    data = substr(data, 64, length-1);
  else
    data = NULL;

  return mklist(header, data);

}

#---------------------------------------------------------#
# Function    : smb2_recv                                 #
# Description : Receives and decodes a SMB2 packet        #
#---------------------------------------------------------#

function smb2_recv ()
{
  local_var socket, timeout, length, trailer, ret, header;

  socket = session_get_socket ();
  timeout = session_get_timeout ();

  length = recv(socket:socket, length:4, min:4, timeout:timeout);
  if (strlen(length) != 4)
    return NULL;

  length = 65535 * ord(length[1]) +
           256 * ord(length[2]) +
           ord(length[3]);

  if (length < 64)
    return NULL;

  if (length > 100000)
    length = 100000;

  trailer = recv(socket:socket, length:length, min:length, timeout:timeout);
  if (strlen(trailer) < length )
    return NULL;

  session_set_response(data:trailer);
  ret = decode_smb2(data:trailer);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  # the server must not send anything before the reply as we are not asynchronous
  if (header[3] == STATUS_PENDING)
    return smb2_recv();

  return ret;
}

function smb3_update_preintegrity_hashval(data)
{
  session_set_pi_hash(hash: SHA512(session_get_pi_hash() + data));
}

function smb3_get_signing_key()
{
  local_var session_key, lbl, ctx, signing_key;

  session_key = session_get_mackey();
  if (session_get_dialect() == SMB_DIALECT_0311)
  {
    lbl = raw_string("SMBSigningKey", 0);
    ctx = session_get_pi_hash();
  }
  else
  {
    lbl = raw_string("SMB2AESCMAC", 0);
    ctx = raw_string("SmbSign", 0);
  }
  signing_key = kdf_ctr_hmacsha256(r:32, L:128, key:session_key, label:lbl, context:ctx);

  return signing_key;
}

function smb3_get_encryption_key()
{
  local_var session_key, lbl, ctx, signing_key;

  session_key = session_get_mackey();
  if (session_get_dialect() == SMB_DIALECT_0311)
  {
    lbl = raw_string("SMBC2SCipherKey", 0);
    ctx = session_get_pi_hash();
  }
  else
  {
    lbl = raw_string("SMB2AESCCM", 0);
    ctx = raw_string("ServerIn ", 0);
  }
  signing_key = kdf_ctr_hmacsha256(r:32, L:128, key:session_key, label:lbl, context:ctx);

  return signing_key;
}

function smb3_get_decryption_key()
{
  local_var session_key, lbl, ctx, signing_key;

  session_key = session_get_mackey();
  if (session_get_dialect() == SMB_DIALECT_0311)
  {
    lbl = raw_string("SMBS2CCipherKey", 0);
    ctx = session_get_pi_hash();
  }
  else
  {
    lbl = raw_string("SMB2AESCCM", 0);
    ctx = raw_string("ServerOut", 0);
  }
  signing_key = kdf_ctr_hmacsha256(r:32, L:128, key:session_key, label:lbl, context:ctx);

  return signing_key;
}

function smb3_get_application_key()
{
  local_var session_key, lbl, ctx, signing_key;

  session_key = session_get_mackey();
  if (session_get_dialect() == SMB_DIALECT_0311)
  {
    lbl = raw_string("SMBAppKey", 0);
    ctx = session_get_pi_hash();
  }
  else
  {
    lbl = raw_string("SMB2APP", 0);
    ctx = raw_string("SmbRpc", 0);
  }
  signing_key = kdf_ctr_hmacsha256(r:32, L:128, key:session_key, label:lbl, context:ctx);

  return signing_key;
}

function kdf_ctr_hmacsha256(r, L, key, label, context)
{
  local_var n, h, hash_data, i, idata, Ldata, data0, hval, ret;
  h = 256;
  n = L / h;
  if (L % h) n++;

  ret = "";
  for (i = 1; i <= n; i++)
  {
    idata = int32_to_be(data:i);
    Ldata = int32_to_be(data:L);
    data0 = raw_string(0);
    hash_data = raw_string(idata, label, data0, context, Ldata);
    hval = HMAC_SHA256(key:key, data: hash_data);
    ret = raw_string(ret, hval);
  }

  if (strlen(ret) < (L/8))
    return NULL;

  return substr(ret, 0, L/8 - 1);
}

function int32_to_be(data)
{
  return raw_string((data & 0xff000000) >> 24, (data & 0xff0000) >> 16, (data & 0xff00) >> 8, data & 0xff);
}

function smb2_mac(key, data)
{
  local_var dialect, signing_key;

  dialect = session_get_dialect();
  if (dialect >= SMB_DIALECT_0300)
  {
    # Generate signing key
    signing_key = smb3_get_signing_key();
    return crypto_mac(type:'CMAC_AESCBC', data:data, key:signing_key);
  }
  else
  {
    return HMAC_SHA256(key:key, data:data);
  }
}

#---------------------------------------------------------#
# Function    : smb2_sendrecv                             #
# Description : Sends and receives a SMB2 packet          #
#---------------------------------------------------------#

function smb2_sendrecv(command, data)
{
  local_var header, netbios, socket, length, signature, key, dialect, signed_packet, packet;

  signed_packet = FALSE;
  key = session_get_mackey();
  dialect = session_get_dialect();

  if (key && dialect < 0x300)
    signed_packet = TRUE;
  else if (key && dialect >= 0x300 && (command != SMB2_NEGOTIATE && command != SMB2_SESSION_SETUP))
    signed_packet = TRUE;

  if (signed_packet)
  {
    header = smb2_header(command:command, status:STATUS_SUCCESS, flags:SMB2_FLAGS_SIGNED);
  }
  else
  {
    header = smb2_header(command:command, status:STATUS_SUCCESS);
  }

  # If the dialect is not negotiated yet, or we have negotiated SMBv3
  if ((dialect == NULL || dialect >= 0x300) && (command == SMB2_NEGOTIATE || command == SMB2_SESSION_SETUP))
    smb3_update_preintegrity_hashval(data:header+null_signature+data);

  if (signed_packet)
  {
    signature = smb2_mac(key:key, data:header+null_signature+data);
    if (strlen(signature) < 16)
      return NULL;
    header = header + substr(signature,0,15);
  }
  else
  {
    header = header + null_signature;
  }

  if (session_get_encrypt_msgs())
  {
    packet = smb3_encrypt_packet(packet:header+data);
  }
  else
  {
    packet = header+data;
  }

  length = strlen(packet);
  netbios = netbios_header (type:0, length:length) + packet;

  socket = session_get_socket();
  send (socket:socket, data:netbios);

  if (session_get_mackey())
    session_increase_sequencenumber();

  return smb2_recv ();
}

#---------------------------------------------------------#
# Function    : smb2_session_setup                        #
# Description : Performs a SMB2 session setup             #
#---------------------------------------------------------#

function smb2_session_setup(login, password, hash, domain)
{
  local_var data, ret, securityblob, header, length, sblob;
  local_var challenge, d_name, flags, mackey, secmode;

  securityblob = ntlmssp_negotiate_securityblob ();

  data = raw_word( w:25)                   + # StructureSize
         raw_byte( b:0)                    + # VcNumber
         raw_byte( b:1)                    + # SecurityMode
         raw_dword(d:0)                    + # Capabilities
         raw_dword(d:0)                    + # Channel
         raw_word( w:88)                   + # SecurityBufferOffset
         raw_word( w:strlen(securityblob)) + # SecurityBufferLength
         raw_qword(q:0)                    + # PreviousSessionId
         securityblob;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_MORE_PROCESSING_REQUIRED)
    return NULL;

  session_set_sid(sid:header[11]);

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  length = get_word(blob:data, pos:6);
  if (strlen(data) < (length+8))
    return NULL;

  securityblob = substr(data, 8, length+7);

  challenge = ntlmssp_parse_challenge (data:securityblob);
  if (isnull(challenge))
    return NULL;

  sblob = challenge[3];
  session_set_addrlist(addrlist:challenge[3]);

  d_name = get_string2 (blob:challenge[1], pos:0, len:strlen(challenge[1]));
  challenge = challenge[0];

  session_set_host_info (domain:d_name, os:NULL, lan:NULL);

  if (login)
  {
    if (password)
    {
      password = cstring (string:password, _null:1);
    }
    login = cstring (string:login, _null:1);
    domain = cstring (string:domain, _null:1);
  }
  else
  {
    login = password = domain = hash = NULL;
  }

  # forceip:TRUE -> Only use an IP address instead of an FQDN for NTLMv2_Response structure
  # This is a behavior in MS SMB implementation in windows server 2016 with SPN validation
  securityblob = ntlmssp_auth_securityblob (password:password,login:login,hash:hash,domain:domain,challenge:challenge,sblob:sblob,forceip:TRUE);
  if (isnull(securityblob))
    return NULL;

  mackey = securityblob[0];
  securityblob = securityblob[1];

  secmode = session_get_secmode();

  data = raw_word( w:25)                   + # StructureSize
         raw_byte( b:0)                    + # VcNumber
         raw_byte( b:secmode)              + # SecurityMode
         raw_dword(d:0)                    + # Capabilities
         raw_dword(d:0)                    + # Channel
         raw_word( w:88)                   + # SecurityBufferOffset
         raw_word( w:strlen(securityblob)) + # SecurityBufferLength
         raw_qword(q:0)                    + # PreviousSessionId
         securityblob;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  if (secmode)
    session_set_mackey(key:mackey);

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  length = get_word(blob:data, pos:6);
  if (strlen(data) < (length+8))
    return NULL;

  securityblob = substr(data, 8, 8+length-1);

  flags = get_word(blob:data, pos:2);

  challenge = ntlmssp_parse_response (data:securityblob);
  if (isnull(challenge) || (challenge != 0)) # Accept Completed
    return NULL;

  return flags;
}

#---------------------------------------------------------#
# Function    : smb2_session_setup_kerberos               #
# Description : Performs a SMB2 session setup             #
#---------------------------------------------------------#

function smb2_session_setup_kerberos(login, password, realm, host)
{
  local_var data, ret, securityblob, header, length;
  local_var challenge, d_name, flags, mackey, secmode;
  local_var kerb_data, key;

  securityblob = ntlmssp_negotiate_securityblob ();

  kerb_data = kerberos_securityblob (login:login,password:password,realm:realm,host:host);
  if (isnull(kerb_data))
    return NULL;

  securityblob = kerb_data[1];

  data = raw_word( w:25)                   + # StructureSize
         raw_byte( b:0)                    + # VcNumber
         raw_byte( b:1)                    + # SecurityMode
         raw_dword(d:0)                    + # Capabilities
         raw_dword(d:0)                    + # Channel
         raw_word( w:0x58)                 + # SecurityBufferOffset
         raw_word( w:strlen(securityblob)) + # SecurityBufferLength
         raw_qword(q:0)                    + # PreviousSessionId
         securityblob;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  session_set_sid(sid:header[11]);

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  length = get_word(blob:data, pos:6);
  if (strlen(data) < (length+8))
    return NULL;

  securityblob = substr(data, 8, length+7);
  key = check_kerberos_response (data:securityblob, key:kerb_data[0]);
  if (isnull(key))
    return NULL;

  secmode = session_get_secmode();

  if (secmode)
  {
    if (key[0] == 0)
      key = kerb_data[0];
    else
      key = key[1];

    # [MS-SMB2] section 3.2.5.3.1
    if (strlen(key) >= 16)
      key = substr(key, 0, 15);
    else
      key = key + crap(data:'\x00', length: 16 - strlen(key));

    session_set_mackey (key:key);
  }

  return data;
}

#---------------------------------------------------------#
# Function    : smb2_tree_connect                         #
# Description : Performs a SMB2 tree connect              #
#---------------------------------------------------------#

function smb2_tree_connect(path)
{
  local_var data, ret, header, cpath;

  cpath = cstring (string:"\\", _null:1) + cstring (string:session_get_hostname(), _null:1) + cstring (string:"\", _null:1) + cstring (string:path, _null:1);

  data = raw_word(w:9)             + # StructureSize
         raw_word(w:0)             + # Reserved
         raw_word(w:0x48)          + # PathOffset
         raw_word(w:strlen(cpath)) + # PathLength
         cpath;                      # Buffer

  ret = smb2_sendrecv(command:SMB2_TREE_CONNECT, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc:smb_get_problem_description(op_desc:"connect", text:"the '" + path + "' share"));

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  session_set_tid(tid:header[10]);

  data = ret[1];
  if (strlen(data) != 16)
    return NULL;

  ret = NULL;
  ret[0] = get_word( blob:data, pos:0);  # StructureSize
  ret[1] = get_byte( blob:data, pos:2);  # ShareType
  ret[2] = get_byte( blob:data, pos:3);  # Reserved
  ret[3] = get_dword(blob:data, pos:4);  # ShareFlags
  ret[4] = get_dword(blob:data, pos:8);  # Capabilities
  ret[5] = get_dword(blob:data, pos:12); # MaximalAccess

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_connect                              #
# Description : Performs a SMB2 connect                   #
#---------------------------------------------------------#
global_var UNIT_TESTING = FALSE;

function smb2_create(name, desired_access, flags_attributes, share_mode, create_disposition, create_options, dont_record_access)
{
  local_var data, ret, header, name_len, cname;

  if(isnull(name) || name =="")
  {
    # [MS-SMB2] section 2.2.13
    # "In the request, the Buffer field MUST be at least one byte in length."
    cname = raw_string(0x00);

    # [MS-SMB2] section 2.2.13
    # "A zero length file name indicates a request to open the root of the share."
    name_len = 0;
  }
  else
  {
    # Remove any preceding or terminating path separators (Per [MS-FSCC] 2.1.5)
    # Allow all non-forbidden characters such as {} the "name" parameter is a full path
    # with embedded path separators.
    name = ereg_replace(string:name, pattern:"^([\/\\]*)(.*[^\/\\])([\/\\]*)$", replace:"\2");

    cname = cstring(string:name, _null:1);
    name_len = strlen(cname);
  }

  #Unit tests for now will just test path processing
  if(UNIT_TESTING)
  {
    return name;
  }

  data = raw_word( w:0x39)               + # StructureSize
         raw_byte( b:0)                  + # SecurityFlags
         raw_byte( b:0)                  + # RequestedOplockLevel
         raw_dword(d:2)                  + # ImpersonationLevel
         raw_qword(q:0)                  + # SmbCreateFlags
         raw_qword(q:0)                  + # Reserved
         raw_dword(d:desired_access)     + # DesiredAccess
         raw_dword(d:flags_attributes)   + # FileAttributes
         raw_dword(d:share_mode)         + # ShareAccess
         raw_dword(d:create_disposition) + # CreateDisposition
         raw_dword(d:create_options)     + # CreateOptions
         raw_word( w:0x78)               + # NameOffset
         raw_word( w:name_len)           + # NameLength
         raw_dword(d:0)                  + # CreateContextsOffset
         raw_dword(d:0)                  + # CreateContextsLength
         cname;                            # Buffer

  ret = smb2_sendrecv(command:SMB2_CREATE, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if(header[3] == STATUS_ACCESS_DENIED && !dont_record_access)
  {
    if(isnull(name) || !strlen(name))
    {
      name = smb_get_open_share_name(tid:session_get_tid());
      smb_set_kb_auth_problem(desc: "opening the share '" + name + "'");
    }
    else
      smb_set_kb_auth_problem(desc:smb_get_problem_description(op_desc:"open", text:"'" + name + "'"));
  }

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) != 88)
    return NULL;

  ret = NULL;
  ret[0] = substr(data, 64, 79); # FileId
  ret[1] = substr(data, 48, 63); # EndofFile

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_write                                #
# Description : Writes to a pipe/file                     #
#---------------------------------------------------------#

function smb2_write(fid, offset, mode, data)
{
  local_var ret, header;

  data = raw_word( w:0x31)         + # StructureSize
         raw_word( w:0x70)         + # DataOffset
         raw_dword(d:strlen(data)) + # Length
         raw_qword(q:offset)       + # Offset
                     fid           + # FileId
         raw_dword(d:0)            + # Channel
         raw_dword(d:0)            + # RemainingBytes
         raw_word( w:0)            + # WriteChannelInfoOffset
         raw_word( w:0)            + # WriteChannelInfoLength
         raw_dword(d:0)            + # Flags
         data;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_WRITE, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(fid), op_desc:"write"));

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 16)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob: data, pos:0);  # StructureSize
  ret[1] = get_word(blob: data, pos:2);  # Reserved
  ret[2] = get_dword(blob:data, pos:4);  # Count
  ret[3] = get_dword(blob:data, pos:8);  # Remaining
  ret[4] = get_word(blob: data, pos:12); # WriteChannelInfoOffset
  ret[5] = get_word(blob: data, pos:14); # WriteChannelInfoLength

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_read                                 #
# Description : Reads from a pipe/file                    #
#---------------------------------------------------------#

function smb2_read(fid, offset, length)
{
  local_var data, ret, header, pos;

  data = raw_word( w:0x31)   + # StructureSize
         raw_byte( b:0)      + # Padding
         raw_byte( b:0)      + # Reserved
         raw_dword(d:length) + # Length
         raw_qword(q:offset) + # Offset
                     fid     + # FileId
         raw_dword(d:0)      + # MininumCount
         raw_dword(d:0)      + # Channel
         raw_dword(d:0)      + # RemainingBytes
         raw_word( w:0)      + # WriteChannelInfoOffset (Reserved through 2.1)
         raw_word( w:0)      + # WriteChannelInfoLength (Reserved through 2.1)
         raw_byte( b:0);       # Buffer

  ret = smb2_sendrecv(command:SMB2_READ, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(fid), op_desc:"read"));

  if (header[3] != STATUS_SUCCESS && header[3] != STATUS_BUFFER_OVERFLOW)
    return NULL;

  data = ret[1];
  if (strlen(data) < 16)
    return NULL;

  ret = NULL;
  ret[0] = get_word( blob:data, pos:0);  # StructureSize
  ret[1] = get_byte( blob:data, pos:2);  # DataOffset
  ret[2] = get_byte( blob:data, pos:3);  # Reserved
  ret[3] = get_dword(blob:data, pos:4);  # DataLength
  ret[4] = get_dword(blob:data, pos:8);  # DataRemaining
  ret[5] = get_dword(blob:data, pos:12); # Reserved2

  if (ret[3] > 0)
  {
    pos = ret[1] - 0x40;
    if (strlen(data) < pos+ret[3])
      return NULL;
    ret[6] = substr(data, pos, pos+ret[3]-1);
  }
  else
    ret[6] = NULL;

  return ret[6];
}

#---------------------------------------------------------#
# Function    : smb2_ioctl                                #
# Description : Performs a IOCTL operation on the file    #
#               descriptor                                #
#---------------------------------------------------------#

function smb2_ioctl(fid, code, data)
{
  local_var ret, header, type, pos, max_resp_size;

  if (code == FSCTL_PIPE_TRANSCEIVE)
    type = SMB2_0_IOCTL_IS_FSCTL;

  #MaxOutputResponse = MaxTransactSize - sizeof(dcerpc structure);
  max_resp_size = session_get_buffersize() - 0x400;
  if (max_resp_size < 1024) max_resp_size = 1024;

  data = raw_word( w:0x39)          + # StructureSize
         raw_word( w:0)             + # Reserved
         raw_dword(d:code)          + # CtlCode
                     fid            + # FileId
         raw_dword(d:0x78)          + # InputOffset
         raw_dword(d:strlen(data))  + # InputCount
         raw_dword(d:0)             + # MaxInputResponse
         raw_dword(d:0)             + # OutputOffset
         raw_dword(d:0)             + # OutputCount
         raw_dword(d:max_resp_size) + # MaxOutputResponse
         raw_dword(d:type)          + # Flags
         raw_dword(d:0)             + # Reserved2
         data;                        # Buffer

  ret = smb2_sendrecv(command:SMB2_IOCTL, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(fid), op_desc:"ioctl"));

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 48)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data,  pos:0);  # StructureSize
  ret[1] = get_word(blob:data,  pos:2);  # Reserved
  ret[2] = get_dword(blob:data, pos:4);  # CtlCode
  ret[3] = substr(data, 8, 23);          # FileId
  ret[4] = get_dword(blob:data, pos:24); # InputOffset
  ret[5] = get_dword(blob:data, pos:28); # InputCount
  ret[6] = get_dword(blob:data, pos:32); # OutputOffset
  ret[7] = get_dword(blob:data, pos:36); # OutputCount
  ret[8] = get_dword(blob:data, pos:40); # Flags
  ret[9] = get_dword(blob:data, pos:44); # Reserved2

  if (ret[5] > 0)
  {
    pos = ret[4] - 0x40;
    if (strlen(data) < pos+ret[5])
      return NULL;
    ret[10] = substr(data, pos, pos+ret[5]-1);
  }
  else
    ret[10] = NULL;

  if (ret[7] > 0)
  {
    pos = ret[6] - 0x40;
    if (strlen(data) < pos+ret[7])
      return NULL;
    ret[11] = substr(data, pos, pos+ret[7]-1);
  }
  else
    ret[11] = NULL;

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_close                                #
# Description : Closes the file descriptor                #
#---------------------------------------------------------#

function smb2_close(fid)
{
  local_var data, ret, header;

  data = raw_word( w:24) + # StructureSize
         raw_word( w:0)  + # Flags
         raw_dword(d:0)  + # Reserved
         fid;              # FileId

  ret = smb2_sendrecv(command:SMB2_CLOSE, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(fid), op_desc:"close"));

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 60)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data,  pos:0);    # StructureSize
  ret[1] = get_byte(blob:data,  pos:2);    # Flags
  ret[2] = get_dword(blob:data, pos:4);    # Reserved
  ret[3] = convert_win64_time_to_unixtime( # CreationTime
            low  : get_dword (blob:data, pos:8),
            high : get_dword (blob:data, pos:8 + 4)
  );
  ret[4] = convert_win64_time_to_unixtime( # LastAccessTime
            low  : get_dword (blob:data, pos:16),
            high : get_dword (blob:data, pos:16 + 4)
  );
  ret[5] = convert_win64_time_to_unixtime( # LastWriteTime
            low  : get_dword (blob:data, pos:24),
            high : get_dword (blob:data, pos:24 + 4)
  );
  ret[6] = convert_win64_time_to_unixtime( # ChangeTime
            low  : get_dword (blob:data, pos:32),
            high : get_dword (blob:data, pos:32 + 4)
  );
  ret[7] = get_qword(blob:data, pos:40);   # AllocationSize
  ret[8] = get_qword(blob:data, pos:48);   # EndofFile
  ret[9] = get_dword(blob:data, pos:56);   # FileAttributes

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_tree_disconnect                      #
# Description : Disconnect from the current tree          #
#---------------------------------------------------------#

function smb2_tree_disconnect()
{
  local_var data, ret, header, tid;

  tid = session_get_tid ();
  if (isnull(tid))
    return 1;

  data = raw_word(w:4) + # StructureSize
         raw_word(w:0);  # Reserved

  ret = smb2_sendrecv(command:SMB2_TREE_DISCONNECT, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 4)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data, pos:0);   # StructureSize
  ret[1] = get_byte(blob:data, pos:2);   # Reserved

  session_set_tid(tid:NULL);

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_logoff                               #
# Description : Logs off                                  #
#---------------------------------------------------------#

function smb2_logoff()
{
  local_var data, ret, header;

  data = raw_word(w:4) + # StructureSize
         raw_word(w:0);  # Reserved

  ret = smb2_sendrecv(command:SMB2_LOGOFF, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 4)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data, pos:0);   # StructureSize
  ret[1] = get_byte(blob:data, pos:2);   # Reserved

  return ret;
}

#---------------------------------------------------------#
# Function    : decode_file_directory_info                #
# Description : Decodes a FileDirectoryInformation        #
#               structure                                 #
#---------------------------------------------------------#

function decode_file_directory_info(data, raw_timestamp)
{
  local_var nextoffset, pos, ret, i, file, len;

  if (!data) return NULL;

  len = strlen(data);
  pos = 0;
  i = 0;
  ret = NULL;

  while (pos < len)
  {
    nextoffset = get_dword(blob:data, pos:pos);
    file = NULL;

    file[0] = get_dword(blob:data, pos:pos+4);   # FileIndex

    if(!raw_timestamp)
    {
      file[1] = convert_win64_time_to_unixtime(    # CreationTime
                  low  : get_dword (blob:data, pos:pos+8),
                  high : get_dword (blob:data, pos:pos+8+4)
      );
      file[2] = convert_win64_time_to_unixtime(    # LastAccessTime
                  low  : get_dword (blob:data, pos:pos+16),
                  high : get_dword (blob:data, pos:pos+16+4)
      );
      file[3] = convert_win64_time_to_unixtime(    # LastWriteTime
                  low  : get_dword (blob:data, pos:pos+24),
                  high : get_dword (blob:data, pos:pos+24+4)
      );
      file[4] = convert_win64_time_to_unixtime(    # ChangeTime
                  low  : get_dword (blob:data, pos:pos+32),
                  high : get_dword (blob:data, pos:pos+32+4)
      );
    }
    else
    {
      file[1] = get_dword(blob:data, pos:pos+8);  # CreationTime
      file[2] = get_dword(blob:data, pos:pos+16); # LastAccessTime
      file[3] = get_dword(blob:data, pos:pos+24); # LastWriteTime
      file[4] = get_dword(blob:data, pos:pos+32); # ChangeTime
    }

    file[5] = get_dword(blob:data, pos:pos+40);  # EndOfFile
    file[6] = get_dword(blob:data, pos:pos+48);  # AllocationSize
    file[7] = get_dword(blob:data, pos:pos+56);  # FileAttributes
    file[8] = get_dword(blob:data, pos:pos+60);  # FileNameLength
    file[9] = get_string2 (blob:data, pos:pos+64, len:file[8]);

    pos = pos + nextoffset;
    ret[i++] = file;

    if (nextoffset == 0)
      break;
  }

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_query_directory                      #
# Description : Queries directory information             #
#---------------------------------------------------------#

function smb2_query_directory(flags, index, pattern, id, raw_timestamp)
{
  local_var data, ret, header;

  pattern = cstring(string:pattern, _null:1);

  data = raw_word( w:33)                         + # StructureSize
         raw_byte( b:FILE_DIRECTORY_INFORMATION) + # FileInformationClass
         raw_byte( b:flags)                      + # Flags
         raw_dword(d:index)                      + # FileIndex
         id                                      + # FileId
         raw_word( w:0x60)                       + # FileNameOffset
         raw_word( w:strlen(pattern))            + # FileNameLength
         raw_dword(d:4096)                       + # OutputBufferLength
         pattern;

  ret = smb2_sendrecv(command:SMB2_QUERY_DIRECTORY, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(id), op_desc:"dir"));

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data, pos:0);   # StructureSize
  ret[1] = get_byte(blob:data, pos:2);   # OutputBufferOffset
  ret[2] = get_dword(blob:data, pos:4);  # OutputBufferLength

  if (strlen(data) < (8+ret[2]))
    return NULL;

  ret[3] = substr(data, 8, 8+ret[2]-1);

  return decode_file_directory_info(data:ret[3], raw_timestamp:raw_timestamp);
}

#---------------------------------------------------------#
# Function    : smb2_query_info                           #
# Description : Queries FID information                   #
#---------------------------------------------------------#

function smb2_query_info(type, class, info, id)
{
  local_var data, ret, header, olen;

  data = raw_word( w:41)    + # StructureSize
         raw_byte( b:type)  + # InfoType
         raw_byte( b:class) + # FileInfoClass
         raw_dword(d:0)     + # OutputBufferLength
         raw_word( w:0)     + # InputBufferOffset
         raw_word( w:0)     + # Reserved
         raw_dword(d:0)     + # InputBufferLength
         raw_dword(d:info)  + # AdditionalInformation
         raw_dword(d:0)     + # Flags
         id;                  # FileId

  ret = smb2_sendrecv(command:SMB2_QUERY_INFO, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(id), op_desc:"query"));

  if (header[3] != STATUS_BUFFER_TOO_SMALL)
    return NULL;

  data = ret[1];
  if (strlen(data) < 12)
    return NULL;

  # SMB 3.1.1 sends back the required buffer size in a different position
  if(session_get_dialect() == SMB_DIALECT_0311)
    olen = get_dword(blob:data, pos:16);
  else
    olen = get_dword(blob:data, pos:8);

  data = raw_word( w:41)    + # StructureSize
         raw_byte( b:type)  + # InfoType
         raw_byte( b:class) + # FileInfoClass
         raw_dword(d:olen)  + # OutputBufferLength
         raw_word( w:0)     + # InputBufferOffset
         raw_word( w:0)     + # Reserved
         raw_dword(d:0)     + # InputBufferLength
         raw_dword(d:info)  + # AdditionalInformation
         raw_dword(d:0)     + # Flags
         id;                  # FileId

  ret = smb2_sendrecv(command:SMB2_QUERY_INFO, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(id), op_desc:"query"));

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  ret = NULL;
  ret[0] = get_word( blob:data, pos:0); # StructureSize
  ret[1] = get_byte( blob:data, pos:2); # OutputBufferOffset
  ret[2] = get_dword(blob:data, pos:4); # OutputBufferLength

  if (strlen(data) < (8+ret[2]))
    return NULL;

  ret[3] = substr(data, 8, 8+ret[2]-1);

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_set_info                             #
# Description : Sets FID information                      #
#---------------------------------------------------------#
function smb2_set_info(type, class, info, id, data)
{
  local_var header, ret;

  data = raw_word( w:33)           + # StructureSize
         raw_byte( b:type)         + # InfoType
         raw_byte( b:class)        + # FileInfoClass
         raw_dword(d:strlen(data)) + # BufferLength
         raw_word( w:0x60)         + # BufferOffset
         raw_word( w:0)            + # Reserved
         raw_dword(d:info)         + # AdditionalInformation
         id                        + # FileId (16 Bytes)
         data;                       # Buffer
  ret = smb2_sendrecv(command:SMB2_SET_INFO, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  if(header[3] == STATUS_ACCESS_DENIED)
    smb_set_kb_auth_problem(desc: smb_get_problem_description(fid:int(id), op_desc:"info"));

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 2)
    return NULL;

  # If successful, the server returns an SMB2_SET_INFO packet
  # that only contains a structure size of 2. [MS-SMB2] section 2.2.40
  ret = get_word(blob:data, pos:0); # StructureSize
  if (ret != 2)
    return NULL;

  return TRUE;
}

function smb2_negotiate_protocol(smb_dialects, smb3_available)
{
  local_var data, header, ret, uuid, smb_capabilities;
  local_var dialect, dialect_count, dialect_list;
  local_var hash_algo, hash_algo_count, hash_algo_list, smb_hash_algos;
  local_var negotiate_context_index, negotiate_context_count, negotiate_context_offset;
  local_var smb_header_len, padding, encryption_data, cipher, cipher_list, cipher_count, smb_ciphers;
  local_var preauth_integrity_data, preauth_integrity_salt;
  local_var resp_dialect, resp_hash_list, resp_salt, resp_cipher_list, resp_hash_name;

  # Generate a UUID for the client
  uuid = encode_uuid(uuid:generate_uuid());
  session_set_client_id(uuid:uuid);

  # If caller doesn't disable smb3 availability, apply default
  if (isnull(smb3_available))
  {
    smb3_available = TRUE;
  }

  # Check SMBv3 crypto built-ins
  if (!defined_func("nasl_level") || nasl_level() < 61006 ||
      !defined_func("crypto_mac") ||
      !defined_func("crypto_encrypt"))
  {
    # GizaNE older than 6.10.6 doesn't have required crypto
    # functions for SMBv3 hashing and message encryption
    smb3_available = FALSE;
  }

  # If caller doesn't specify smb dialects explicitly, use defaults
  if (isnull(smb_dialects))
  {
    # Generate client dialect fields
    if (smb3_available)
    {
      smb_dialects = mklist(
                            SMB_DIALECT_0202,  # SMB 2.0.2: Windows 2008 SMB2 version.
                            SMB_DIALECT_0210,  # SMB 2.1:   Windows 7 SMB2 version.
                            0x222,  # SMB2_22: Early Windows 8 SMB2 version.
                            0x224,  # SMB2_24: Windows 8 beta SMB2 version.
                            SMB_DIALECT_0300,  # SMB 3.0:   Windows 8 SMB3 version. (mostly the same as SMB2_24)
                            SMB_DIALECT_0302,  # SMB 3.0.2: Windows 8.1 SMB3 version.
                            0x310,  # SMB3_10: early Windows 10 technical preview SMB3 version.
                            SMB_DIALECT_0311   # SMB 3.1.1: Windows 10 technical preview SMB3 version (maybe final)
                          );
    }
    else
    {
      smb_dialects = mklist(
                            SMB_DIALECT_0202,  # SMB 2.0.2: Windows 2008 SMB2 version.
                            SMB_DIALECT_0210,  # SMB 2.1:   Windows 7 SMB2 version.
                            0x222,  # SMB2_22: Early Windows 8 SMB2 version.
                            0x224   # SMB2_24: Windows 8 beta SMB2 version.
                          );
    }
  }

  dialect_count = 0;
  dialect_list = '';
  foreach dialect (smb_dialects)
  {
    dialect_count++;
    dialect_list += raw_word(w:dialect);
  }

  # Generate client pre-auth integrity capabilities (SMB 3.1.0+)
  hash_algo_count = 0;
  hash_algo_list = '';
  if (smb3_available)
  {
    smb_hash_algos = mklist(
                              SMB2_HASH_ALGORITHM_SHA_512
                           );
    foreach hash_algo (smb_hash_algos)
    {
      hash_algo_count++;
      hash_algo_list += raw_word(w:hash_algo);
    }
  }
  preauth_integrity_salt = smb3_preauthentication_entropy();
  preauth_integrity_data = raw_word(w:hash_algo_count)                  + # Hash algorithm count
                           raw_word(w:strlen(preauth_integrity_salt))   + # Salt length
                           hash_algo_list                               + # Hash algorithms (variable)
                           preauth_integrity_salt;                        # Salt (variable)

  # Generate client encryption capabilities (SMB 3.1.0+)
  cipher_count = 0;
  cipher_list = '';
  if (smb3_available)
  {
    smb_ciphers = mklist(
                          SMB2_CIPHER_AES_128_CCM,
                          SMB2_CIPHER_AES_128_GCM
                        );
    foreach cipher (smb_ciphers)
    {
      cipher_count++;
      cipher_list += raw_word(w:cipher);
    }
  }
  encryption_data = raw_word(w:cipher_count)         + # CipherCount
                    cipher_list;                       # Ciphers (variable)

  smb_capabilities = 0;
  if (smb3_available)
  {
    smb_capabilities = smb_capabilities | SMB2_GLOBAL_CAP_ENCRYPTION;
  }
  data = raw_word( w:36)                             + # StructureSize (36)
         raw_word( w:dialect_count)                  + # DialectCount
         raw_word( w:SMB2_NEGOTIATE_SIGNING_ENABLED) + # SecurityMode
         raw_word( w:0)                              + # Reserved
         raw_dword(d:smb_capabilities)               + # Capabilities
         uuid                                        + # Client GUID
         raw_dword(d:0)                              + # NegotiateContextOffset
         raw_word( w:0)                              + # NegotiateContextCount
         raw_word( w:0)                              + # Reserved
         dialect_list;                                 # Dialects (variable)

  # Align Negotiate Context to 8-bytes (padding dependent on data length)
  padding = crap(data:'\x00', length: (8 - strlen(data) % 8) % 8);

  # Replace NegotiateContextOffset and Count (dependent on padding length)
  smb_header_len = 0x40;
  negotiate_context_offset = raw_dword(d:smb_header_len + 12 + strlen(uuid) + 8 + strlen(dialect_list) + strlen(padding));
  negotiate_context_count = raw_word(w:2);
  negotiate_context_index = 12 + strlen(uuid);
  data[negotiate_context_index]   = raw_byte(b:negotiate_context_offset[0]);
  data[negotiate_context_index+1] = raw_byte(b:negotiate_context_offset[1]);
  data[negotiate_context_index+2] = raw_byte(b:negotiate_context_offset[2]);
  data[negotiate_context_index+3] = raw_byte(b:negotiate_context_offset[3]);
  data[negotiate_context_index+4] = raw_byte(b:negotiate_context_count[0]);
  data[negotiate_context_index+5] = raw_byte(b:negotiate_context_count[1]);

  data += padding                                       + # Padding (variable)
  # Pre-Auth Integrity Capabilities
          raw_word( w:1)                                + # ContextType (SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
          raw_word( w:strlen(preauth_integrity_data))   + # DataLength
          raw_dword(d:0)                                + # Reserved
          preauth_integrity_data;                         # Data (variable)

  # Align Negotiate Context to 8-bytes (padding dependent on data length)
  padding = crap(data:'\x00', length: (8 - strlen(data) % 8) % 8);

  data += padding                                       + # Padding (variable)
  # Encryption Capabilities
          raw_word( w:2)                                + # ContextType (SMB2_ENCRYPTION_CAPABILITIES)
          raw_word( w:strlen(encryption_data))          + # DataLength
          raw_dword(d:0)                                + # Reserved
          encryption_data;                                # Data (variable)

  # Reset Pre-Authentication hash value for each negotiate request
  session_set_pi_hash(hash:crap(data:'\x00', length:64));
  ret = smb2_sendrecv(command:SMB2_NEGOTIATE, data:data);
  if (isnull(ret))
    return NULL;

  ret = smb2_parse_negotiate_response(header:ret[0], data:ret[1]);

  resp_dialect = ret[2];
  resp_hash_list = ret[18];
  resp_salt = ret[19];
  resp_cipher_list = ret[20];

  # SMB3
  if (resp_dialect >= SMB_DIALECT_0311)
  {
    resp_hash_name = '';
    if (resp_hash_list[0] == 0x01)
      resp_hash_name = 'SMB2_HASH_ALGORITHM_SHA_512';
  }

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_decode_parse_negotiate_response      #
# Description : Decodes and parses SMB2 negotiate response#
#---------------------------------------------------------#

function smb2_decode_parse_negotiate_response(data)
{
  local_var ret;
  ret = decode_smb2(data:data);
  if (isnull(ret))
    return NULL;

  return smb2_parse_negotiate_response(header:ret[0], data:ret[1]);
}
#---------------------------------------------------------#
# Function    : smb2_parse_negotiate_response             #
# Description : Parses SMB2 negotiate response            #
#---------------------------------------------------------#

function smb2_parse_negotiate_response(header, data)
{
  local_var ret, pos, negotiate_context;

  if (header[3] != STATUS_SUCCESS)
    return NULL;

  if (strlen(data) < 64)
    return NULL;

  ret = NULL;
  ret[0] =  get_word( blob:data, pos:0);  # StructureSize
  ret[1] =  get_word( blob:data, pos:2);  # SecurityMode
  ret[2] =  get_word( blob:data, pos:4);  # DialectRevision
  ret[3] =  get_word( blob:data, pos:6);  # NegotiateContextCount (SMBv311+)
  ret[4] =  substr(data, 8, 23);          # ServerGuid
  ret[5] =  get_dword(blob:data, pos:24); # Capabilities
  ret[6] =  get_dword(blob:data, pos:28); # MaxTransactSize
  ret[7] =  get_dword(blob:data, pos:32); # MaxReadSize
  ret[8] =  get_dword(blob:data, pos:36); # MaxWriteSize
  ret[9] =  convert_win64_time_to_unixtime( # SystemTime
              low  : get_dword (blob:data, pos:40),
              high : get_dword (blob:data, pos:40 + 4)
  );
  ret[10] = convert_win64_time_to_unixtime( # ServerStartTime
              low  : get_dword (blob:data, pos:48),
              high : get_dword (blob:data, pos:48 + 4)
  );
  ret[11] = get_word( blob:data, pos:56); # SecurityBufferOffset
  ret[12] = get_word( blob:data, pos:58); # SecurityBufferLength
  ret[13] = get_dword(blob:data, pos:60); # NegotiateContextOffset (SMBv311+)

  ret[15] = NULL; # full NegotiateContext array
  ret[16] = NULL; # parsed preauth integrity capability
  ret[17] = NULL; # parsed encryption capability
  ret[18] = NULL; # preauth hash list
  ret[19] = NULL; # hash salt
  ret[20] = NULL; # encryption cipher list

  if (ret[12] > 0)
  {
    pos = ret[11] - 0x40;
    if (strlen(data) < pos+ret[12])
      return NULL;
    ret[14] = substr(data, pos, pos+ret[12]-1);
  }
  else
    ret[14] = NULL;


  # Parse Negotiate
  if (ret[2] >= SMB_DIALECT_0311 && ret[3] > 0)
  {
    pos = ret[13] - 0x40;
    ret[15] = smb3_parse_negotiate_context(data:substr(data, pos, strlen(data)), count:ret[3]);
  }

  foreach negotiate_context (ret[15])
  {
    if (negotiate_context[0] == SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
    {
      ret[16] = negotiate_context[4]; # Parsed hash struct
      ret[18] = ret[16][2]; # hash list
      ret[19] = ret[16][3]; # salt
    }
    else if (negotiate_context[0] == SMB2_ENCRYPTION_CAPABILITIES)
    {
      ret[17] = negotiate_context[4]; # Parsed ciphers struct
      ret[20] = ret[17][1]; # cipher list
    }
  }


  return ret;
}

#---------------------------------------------------------#
# Function    : smb3_parse_negotiate_context              #
# Description : Parses N NegotiateContext structs from    #
#               negotiate response                        #
# Note        : Function assumes data starts at an 8-byte #
#               aligned offset                            #
#---------------------------------------------------------#

function smb3_parse_negotiate_context(data, count)
{
  local_var ret, arr, i, j, offset, context_type, data_len;
  local_var struct_offset, struct, hash_list, cipher_list;

  ret = NULL;
  offset = 0;
  for (i = 0; i < count; i++)
  {
    arr = NULL;
    arr[0] = get_word(blob:data,  pos:offset+0);            # ContextType
    arr[1] = get_word(blob:data,  pos:offset+2);            # DataLength
    arr[2] = get_dword(blob:data, pos:offset+4);            # Reserved
    if (strlen(data) < offset+8+arr[1])
      return NULL;
    arr[3] = substr(data, offset+8, offset+8+arr[1]-1);     # Data

    if (arr[0] == SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
    {
      struct = NULL;
      struct[0] = get_word(blob:arr[3], pos:0); # Hash Algorithm Count
      struct[1] = get_word(blob:arr[3], pos:2); # Salt Length
      hash_list = NULL;
      struct_offset = 4;
      for (j = 0; j < struct[0]; j++)
      {
        hash_list[j] = get_word(blob:arr[3], pos:struct_offset); # HashAlgorithms
        struct_offset += 2;
      }
      struct[2] = hash_list;
      if (strlen(arr[3]) < struct_offset+struct[1])
        return NULL;
      struct[3] = substr(arr[3], struct_offset, struct_offset+struct[1]-1); # Salt

      arr[4] = struct;
    }
    else if (arr[0] == SMB2_ENCRYPTION_CAPABILITIES)
    {
      struct = NULL;
      struct[0] = get_word(blob:arr[3], pos:0); # Cipher Count
      cipher_list = NULL;
      struct_offset = 2;
      for (j = 0; j < struct[0]; j++)
      {
        cipher_list[j] = get_word(blob:arr[3], pos:struct_offset); # Ciphers
        struct_offset += 2;
      }
      struct[1] = cipher_list;

      arr[4] = struct;
    }
    else
      arr[4] = NULL;

    offset += 2 + 2 + 4 + arr[1];
    # 8-byte align
    offset = offset + (8 - (((offset-1) % 8)+1));
    ret[i] = arr;
  }

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_login                                #
# Description : Logs in using SMB2 protocol               #
#---------------------------------------------------------#

function smb2_login (negotiate,login,password,domain,lm_hash,ntlm_hash)
{
  local_var ret, flags;
  local_var SecurityMode, Dialect, Capabilities, SecurityBlob, MaxBufferSize, HashList, Salt, CipherList;
  local_var spnego, michlist, host, realm, Extended;
  local_var hash;
  local_var only_kerb;

  if (!isnull(ntlm_hash))
    hash = ntlm_hash;
  else
    hash = NULL;

  ret = smb2_decode_parse_negotiate_response(data:negotiate);
  if (isnull(ret))
    return NULL;

  session_set_smb2(flag:TRUE);
  session_set_unicode(unicode:1);

  ret = smb2_negotiate_protocol();

  if (isnull(ret))
    return NULL;

  SecurityMode  = ret[1];
  Dialect       = ret[2];
  Capabilities  = ret[5];
  SecurityBlob  = ret[14];
  MaxBufferSize = ret[8];
  HashList      = ret[18];
  Salt          = ret[19];
  CipherList    = ret[20];

  session_set_dialect(dialect:Dialect);
  if (Dialect == SMB_DIALECT_0300 || Dialect == SMB_DIALECT_0302)
  {
    session_set_encrypt_algo(data:SMB2_CIPHER_AES_128_CCM);
  }
  else
  {
    if (max_index(ret[18]) >= 1)
      session_set_hash_algo(data:ret[18][0]);
    if (max_index(ret[20]) >= 1)
      session_set_encrypt_algo(data:ret[20][0]);
  }

  spnego = der_parse_spnego_init (sdata:SecurityBlob);
  if(
      !isnull(spnego) && (spnego[3] != NULL) &&
      (spnego[3] != "not_defined_in_RFC4178@please_ignore") &&
      (toupper(spnego[3]) != "NONE") # samba
    )
  {
    michlist = spnego[3];
    host = ereg_replace (pattern:"(.*?)\$?@.*", string:michlist, replace:"\1");
    realm = ereg_replace (pattern:".*\$?@(.*)", string:michlist, replace:"\1");
    Extended = 2; # Kerberos
  }
  else if(!isnull (spnego) && (spnego[0] != NULL) && '1.2.840.48018.1.2.2' >< spnego[0])
  {
    # Check if Kerberos is supported by server, if so use it for auth
    # 1.2.840.48018.1.2.2  -> Microsoft Kerberos 5
    # 1.2.840.113554.1.2.2 -> Kerberos 5
    realm  = domain;
    host   =  kb_smb_name();
    if (isnull(host) || host == get_host_ip())
      host = get_host_name();
    Extended = 2;
  }
  else
    Extended = 1;

  # handle message signing only if server requires it (Or smb3+)
  if (SecurityMode & 2 || Dialect >= SMB_DIALECT_0300)
    session_set_secmode(mode:SecurityMode);

  if (Capabilities & CAP_EXTENDED_SECURITY)
    session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);

  session_set_server_max_size (size:MaxBufferSize);
  if (MaxBufferSize > (session_get_buffersize() - 0x100))
  {
    if(MaxBufferSize + 0x100 > SMB2_MAX_OUTPUT_RESPONSE)
      session_set_buffersize(size:SMB2_MAX_OUTPUT_RESPONSE);
    else
      session_set_buffersize(size:MaxBufferSize+0x100);
  }
  if((Extended == 2) && defined_func ("open_sock_kdc") && get_kb_item('KerberosAuth/enabled') && login && password && realm)
  {
    ret = smb2_session_setup_kerberos(login:login, password:password, realm:realm, host:host);
    if (!isnull(ret))
      return TRUE;

    only_kerb = get_kb_item ("SMB/only_use_kerberos");
    if (only_kerb)
      return FALSE;
  }

  # Do NTLMSSP  if kerberos fails
  flags = smb2_session_setup(login:login, password:password, hash:hash, domain:domain);
  if (isnull (flags))
    return FALSE;

  if ((flags & SMB2_SESSION_FLAG_ENCRYPT_DATA) && !isnull(session_get_encrypt_algo()))
    session_set_encrypt_msgs(data:TRUE);

  return TRUE;
}


#---------------------------------------------------------#
# Function    : smb3_encrypt_packet                       #
# Description : Returns an encrypted SMB transform        #
#               packet                                    #
#---------------------------------------------------------#

function smb3_encrypt_packet(packet)
{
  local_var short_header, header, alg, nonce, key, enc, i;


  short_header =                                         # ProtocolId
                                                         # Signature
                                                         # Nonce
                 raw_dword(d:strlen(packet))           + # Original Message Size
                 raw_word(w:0)                         + # Reserved
                 raw_word(w:1)                         + # Encryption Algorithm
                 session_get_sid();                      # SessionId

  alg = session_get_encrypt_algo();
  key = smb3_get_encryption_key();
  if (alg == SMB2_CIPHER_AES_128_CCM)
  {
    nonce = NULL;
    for (i=0; i<11; i++)
      nonce += raw_string(rand()&0xFF);
    short_header = nonce + crap(data:'\x00', length:16 - strlen(nonce)) + short_header;
    enc = crypto_encrypt(type:'aes_ccm', data:packet, key:key, iv:nonce, options:{taglen:16, aad:short_header});
  }
  else if (alg == SMB2_CIPHER_AES_128_GCM)
  {
    nonce = NULL;
    for (i=0; i<12; i++)
      nonce += raw_string(rand()&0xFF);
    short_header = nonce + crap(data:'\x00', length:16 - strlen(nonce)) + short_header;
    enc = crypto_encrypt(type:'aes_gcm', data:packet, key:key, iv:nonce, options:{taglen:16, aad:short_header});
  }
  else
    return NULL;

  if (isnull(enc))
    return NULL;

  header = '\xFDSMB'                             + # ProtocolId
           enc.tag                               + # Signature
           short_header;

  return header + enc.ciphertext;
}


#---------------------------------------------------------#
# Function    : smb3_decrypt_packet                       #
# Description : Returns a decrypted SMB packet            #
#---------------------------------------------------------#

function smb3_decrypt_packet(packet)
{
  local_var ret, short_header, cipher_text, alg, key, nonce, dec;

  if (strlen(packet) < 52)
    return NULL;

  ret = NULL;

  ret[0]  = substr( packet, 0, 3);           # ProtocolId (\xFDSMB)
  ret[1]  = substr( packet, 4, 19);          # Signature
  ret[2]  = substr( packet, 20, 35);         # Nonce
  ret[3]  = get_dword( blob:packet, pos:36); # Original Message Size
  ret[4]  = get_word(  blob:packet, pos:40); # Reserved
  ret[5]  = get_word(  blob:packet, pos:42); # Encryption Algorithm
  ret[6]  = substr( packet, 44, 51);         # SessionId

  short_header = substr( packet, 20, 51);

  if (strlen(packet) > 52)
    cipher_text = substr(packet, 52, strlen(packet));
  else
    cipher_text = NULL;

  alg = session_get_encrypt_algo();
  key = smb3_get_decryption_key();
  if (alg == SMB2_CIPHER_AES_128_CCM)
  {
    nonce = substr(ret[2], 0, 10);
    dec = crypto_decrypt(type:'aes_ccm', data:cipher_text, key:key, iv:nonce, options:{tag:ret[1], aad:short_header});
  }
  else if (alg == SMB2_CIPHER_AES_128_GCM)
  {
    nonce = substr(ret[2], 0, 11);
    dec = crypto_decrypt(type:'aes_gcm', data:cipher_text, key:key, iv:nonce, options:{tag:ret[1], aad:short_header});
  }
  else
    return NULL;

  return dec;
}


#---------------------------------------------------------#
# Function    : smb3_preauthentication_entropy            #
# Description : Returns a deterministic salt for smb3     #
#---------------------------------------------------------#

function smb3_preauthentication_entropy()
{
  local_var s, x, i;

  s = '\x7a\xaf\xe4\xd9\x4f\x0f\xf4\xed' +
      '\x6a\x56\x1a\xc4\xf6\x2b\x60\x55' +
      '\x8a\xff\x72\x28\x12\xdf\x8d\x73' +
      '\x72\xf4\xd4\x9e\x54\x2f\xb0\xe5';

  x = rand() % 256;
  for (i=0;i<strlen(s);i++)
  {
    s[i] = raw_string((ord(s[i]))^((x+(53*i))%256));
  }
  return s;
}
