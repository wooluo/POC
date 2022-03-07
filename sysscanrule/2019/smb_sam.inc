#TRUSTED 41432a6d5cd050ea13680c31cf3c67f9791cb234da0a3299ac67968ad61cfdc895be3e5db8905c6f101f2a6930fc58d2ceed1c75d84eb429e6412e2440e794398edcb71a7d35d6b563f2bf8d8b1d36c0f013e53ef7a3779a6632a5464d4843bdc91fd2c2223cddf9f72227b147e40fda427c1e65465c4fa806ea3a5c1a231643ce7e60e3254fecbda03741ecf44add37c7d18afe1660913680cf74d77ae79159d532653befb9ba816db50697c1f8c564cecaa7705f8e8fc6211e69a6060e1162298d44ac42bf269dabbef6e2c69ddff0b446f3d2ce2a3381577c38ee569cfdedc05028e3729121fda2b1853baf27b426f82f96f7258b1e14200bdba1df57245c0b29065ba6d694805596f842df02a35c1320e11ea797ef27102c423629cd2ea7738e3b22f4362e3b43e673799ceb28e8e3b99c3cb6a6e8733c4bf23294613a3c0bc8c3a8364bae7060d8b04472b58d2f9eec52192afa323250198cd9a954c55b0dd8eabf3df1c618cbebbca9d6e84711dfa922eac712d3cb09af7895feffab41409aabf6d0d786df2028daaa83509178e38863b76e9ce187ff40a5dddc184d1c684b0773d8b8584cfb8301eb70e2ab0bdf04a4448f3ca7d4f3c6d9c486983a65d90a039cebb912bf0cfa04c23f4b102c861cafce9c032a02f1215b9ce88dfa3055cc1b3d990627d71cd34a0df4cd96fd05a7a698fa6e68dce0056c4fad83f089
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
# smb_sam.inc 
# Revision: 1.8
#

#==================================================================#
# Section 6a. SAM API                                              #
#==================================================================#


##
# Connects to the remote SAM pipe.
# @return  Returns an array : ret[0] : registry handle
#                             ret[1] : registry pipe
#                             ret[2] : 1 (Pipe handle)
##

function SamConnect2 ()
{
 local_var fid, ret, data, resp, rep;

 fid = bind_pipe (pipe:"samr", uuid:"12345778-1234-abcd-ef00-0123456789ac", vers:1);
 if (isnull (fid))
   return NULL;

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +
        raw_dword (d:0x30)        ; # Access mask

 data = dce_rpc_pipe_request (fid:fid, code:OPNUM_SAMCONNECT2, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}


##
# Enumerates SAM domains
#
# @param [handle:int] A SAM server handle.
# @return Returns an array of Domain Names
##

function SamEnumerateDomainsInSamServer (handle)
{
 local_var data, resp, rep, ret, len, ref_id, count;
 local_var actual_count, max_count, offset, name, pos, i;

 data = handle[0]              +  # Handle
 raw_dword (d:0)               +  # NULL handle
 raw_dword (d:0xFFFFFFFF) ;       # Max buf size

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMENUMDOM, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 handle = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 count = get_dword (blob:rep, pos:8);
 ref_id = get_dword (blob:rep, pos:12);
 max_count = get_dword (blob:rep, pos:16);

 # we don't care about size and ref_id
 pos = count * 12 + 20;

 ret = NULL;

 for (i=0; i<count; i++)
 {
  if (strlen (rep) < pos + 12)
    return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (session_is_unicode() == 1)
    actual_count = actual_count * 2;

  if (strlen(rep) < pos + 12 + actual_count)
    return NULL;

  name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);

  pos += actual_count + 12;

  while ((actual_count % 4) != 0)
  {
   actual_count ++;
   pos ++;
  }

  ret[i] = name;
 }

 return ret;
}


##
# Query SAM server for a domain
#
# @param [handle:int] A SAM server handle.
# @param [domain:string] A domain name to search for.
# @return Returns a domain SID
##

function SamLookupDomainInSamServer (handle, domain)
{
 local_var data, resp, rep;

 data = handle[0]                     +  # Handle
 class_parameter (ref_id:0x00020000, name:domain, size:TRUE, _null:FALSE);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMLOOKUP, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 return substr(rep, 8, strlen(rep)-5);
}


##
# Open the given domain sid
#
# @param [handle:int] A SAM server handle.
# @param [sid:array] A domain SID.
# @param [access:int] Requested access permissions.
# @return Returns an array : ret[0] domain handle
#                            ret[1] FID
#                            ret[2] reserved
##

function SamOpenDomain (handle, sid, access)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:ord(sid[1]))     +  # count
        sid ;                            # sid

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMOPENDOM, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;

 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;

 return ret;
}


##
# Query for a user in a domain
#
# @param [handle:int] A SAM domain handle.
# @param [user:string] A user to search for.
# @return Returns a user RID
#
# @remark Supports only one name
##

function SamLookupNamesInDomain (handle, user)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:1)               +  # count
        raw_dword (d:1000)            +  # max count
        raw_dword (d:0)               +  # offset
        raw_dword (d:1)               +  # actual count
 class_parameter (ref_id:0x00020000, name:user, size:TRUE, _null:FALSE);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMLOOKUPNAME, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 36))
   return NULL;

 resp = get_dword (blob:rep, pos:32);
 if (resp != STATUS_SUCCESS)
   return NULL;

 return get_dword (blob:rep, pos:12);
}


##
# Open a handle to a SAM hosted domain object
#
# @param [handle:int] A SAM domain handle.
# @param [rid:int] A RID identifying the object to open.
# @param [access:int] Requested access permissions.
# @param [code:int] An optional SAM OpCode.
# Return      : ret[0] handle
#               ret[1] FID
#               ret[2] reserved
##

function SamOpen (handle, rid, access, code)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:rid)             ;  # count

 data = dce_rpc_pipe_request (fid:handle[1], code:code, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;

 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;

 return ret;
}


##
# Open a SAM domain user handle
#
# @param [handle:int] A SAM domain user handle.
# @param [rid:int] A RID identifying the user to open.
# @param [access:int] Requested access permissions.
#
# @return Returns an array : ret[0] user handle
#                            ret[1] FID
#                            ret[2] reserved
##

function SamOpenUser (handle, rid, access)
{
  return SamOpen (handle:handle, rid:rid, access:access, code:OPNUM_SAMOPENUSER);
}


##
# Open a SAM domain group handle
#
# @param [handle:int] A SAM domain group handle.
# @param [rid:int] A RID identifying the group to open.
# @param [access:int] Requested access permissions.
#
# @return Returns an array : ret[0] group handle
#                            ret[1] FID
#                            ret[2] reserved
##
function SamOpenGroup (handle, rid, access)
{
 return SamOpen (handle:handle, rid:rid, access:access, code:OPNUM_SAMOPENGROUP);
}

##
# Open a SAM domain alias handle
#
# @param [handle:int] A SAM alias handle.
# @param [rid:int] A RID identifying the alias to open.
# @param [access:int] Requested access permissions.
#
# @return Returns an array : ret[0] alias handle
#                            ret[1] FID
#                            ret[2] reserved
##
function SamOpenAlias (handle, rid, access)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:rid)             ;  # count

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMOPENALIAS, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;

 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;

 return ret;
}


##
# Return the groups that a user belongs to
#
# @param [handle:int] A SAM domain handle.
# @return Returns an array of group RIDs
##
function SamGetGroupsForUser (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count;

 data = handle[0] ;

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETGROUPS, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 count  = get_dword (blob:rep, pos:4);
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);

 pos = 16;

 if (strlen(rep) < pos + count * 8 + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  ret[i] = get_dword (blob:rep, pos:pos);
  pos += 8;
 }

 return ret;
}


##
# Return the members of an alias
#
# @param [handle:int] A SAM domain handle.
# @return Returns an array of group/user RIDs
##
function SamGetMembersInAlias (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, num;

 data = handle[0] ;

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETMEMALIAS, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 count  = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 max_count = get_dword (blob:rep, pos:8);

 # we don't care about ref_id
 pos = 12 + count * 4;

 if (strlen(rep) < pos + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos+12)
    return NULL;

  num = get_dword (blob:rep, pos:pos);
  if (strlen(rep) < pos+12+num*4)
    return NULL;

  ret[i] = substr(rep, pos+4, pos+12+num*4-1);
  pos += 12 + num*4;
 }

 return ret;
}


##
# Return the members of a group
#
# @param [handle:int] A SAM domain handle.
# @return Returns an array of RIDs
##
function SamGetMembersInGroup (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, num;

 data = handle[0] ;

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETMEMGROUP, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 count  = get_dword (blob:rep, pos:4);
 pos = 20;

 if (strlen(rep) < pos + count*4 + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  ret[i] = get_dword (blob:rep, pos:pos);
  pos += 4;
 }

 return ret;
}


##
# Map ids to names in a SAM domain
#
# @param [handle:int] A SAM domain handle.
# @param [ids:array] A RID identifying the alias to open.
# @return Returns an array of names
##
function SamLookupIdsInDomain (handle, ids)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, actual_count, offset, id, name;

 data = handle[0]                    +
        raw_dword (d:max_index(ids)) + # count
        raw_dword (d:1000)           + # max_count
        raw_dword (d:0)              + # offset
        raw_dword (d:max_index(ids)) ; # actual count

 foreach id (ids)
   data += raw_dword (d:id);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMLOOKUPIDS, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 count = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 max_count = get_dword (blob:rep, pos:8);

 # we don't care about size and ref_id
 pos = count * 8 + 12;

 ret = NULL;

 for (i=0; i<count; i++)
 {
  if (strlen (rep) < pos + 12)
    return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (session_is_unicode() == 1)
    actual_count = actual_count * 2;

  if (strlen(rep) < pos + 12 + actual_count)
    return NULL;

  name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);

  pos += actual_count + 12;

  while ((actual_count % 4) != 0)
  {
   actual_count ++;
   pos ++;
  }

  ret[i] = name;
 }

 return ret;
}


##
# Query SAM domain for user information
#
# @param [handle:int] A SAM domain handle.
# @return Returns an array of user information  (level 21)
# @remark Incomplete !!!
##
function SamQueryInformationUser (handle)
{
 local_var data, resp, rep, ret, pos, ref_id, level;

 data = handle[0]       +
        raw_word (w:21) ; # level

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMQUERYINFOU, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 52))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 level = get_dword (blob:rep, pos:4);

 pos = 8;

 ret = NULL;
 ret[0] = substr(rep, pos, pos+7);     # last logon time
 ret[1] = substr(rep, pos+8, pos+15);  # last logoff time
 ret[2] = substr(rep, pos+16, pos+23); # pwd last set
 ret[3] = substr(rep, pos+24, pos+31); # acct expiry
 ret[4] = substr(rep, pos+32, pos+39); # pwd can change
 ret[5] = substr(rep, pos+40, pos+47); # pwd must change

 # we don't care about name info (maybe later)
 pos = pos + 20*8   # time + string
           + 8 ;    # RID + GRID

 if (strlen(rep) < pos + 4)
   return NULL;

 ret[6] = get_dword (blob:rep, pos:pos);

 return ret;
}


##
# return domain information
#
# @param [handle:int] An SMB domain handle
# @param [level:int] Kind of domain information requested:
#                       DomainPasswordInformation = 1,
#                       DomainGeneralInformation = 2,
#                       DomainLogoffInformation = 3,
#                       DomainOemInformation = 4,
#                       DomainNameInformation = 5,
#                       DomainReplicationInformation = 6,
#                       DomainServerRoleInformation = 7,
#                       DomainModifiedInformation = 8,
#                       DomainStateInformation = 9,
#                       DomainGeneralInformation2 = 11,
#                       DomainLockoutInformation = 12,
#                       DomainModifiedInformation2 = 13
#                    See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
# @return array of domain information  (level 1,3 or 12)
# @remark  Incomplete !!!
##
function SamQueryInformationDomain (handle, level)
{
 local_var data, resp, rep, ret, pos, ref_id, lev;

 data = handle[0]       +
        raw_word (w:level) ; # level

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMQUERYINFOD, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 8))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 lev = get_word (blob:rep, pos:4);

 pos = 8;

 ret = NULL;

 if (lev == 1)
 {
  if (strlen(rep) != 36)
    return NULL;

  ret[0] = get_word (blob:rep, pos:pos);    # min pass len
  ret[1] = get_word (blob:rep, pos:pos+2);  # pass history len
  ret[2] = get_dword (blob:rep, pos:pos+4); # password must meet complexity requirements
  ret[3] = convert_time_to_sec(time:substr (rep, pos+8, pos+15));    # max pass age
  ret[4] = convert_time_to_sec(time:substr (rep, pos+16, pos+23));   # min pass age
 }
 else if (lev == 3)
 {
  if (strlen(rep) != 20)
    return NULL;

  ret[0] = convert_time_to_sec(time:substr(rep, pos, pos+7));     # force logoff
 }
 else if (lev == 12)
 {
  if (strlen(rep) != 32)
    return NULL;

  ret[0] = convert_time_to_sec(time:substr (rep, pos, pos+7));        # lockout duration
  ret[1] = convert_time_to_sec(time:substr (rep, pos+8, pos+15));     # lockout duration
  ret[2] = get_word (blob:rep, pos:pos+16); # lockout threshold
 }

 return ret;
}


##
# returns user information for a domain
#
# @param : [handle:int] An SMB domain handle
# @return : array of user information
##
function SamQueryDisplayInformation(handle)
{
   local_var data, resp, rep, rid, string_len, pos, idx, names, result;;

   resp = STATUS_MORE_ENTRIES;
   idx = 0;
   names = [];

   while(resp == STATUS_MORE_ENTRIES)
   {
     data = handle[0] +               # domain
            raw_dword(d:1) +          # level - user
            raw_dword(d:idx) +          # index
            raw_dword(d:1) +          # number of names
            raw_dword(d:0x7fffffff);  # tell Windows to send what it has

     data = dce_rpc_pipe_request(fid:handle[1], code:OPNUM_SAMQUERYDISPINFO, data:data);
     if(!data)
       return NULL;

     rep = dce_rpc_parse_response(fid:handle[1], data:data);
     if(!rep || (strlen(rep) < 20))
       return NULL;

     resp = get_dword(blob:rep, pos:strlen(rep)-4);
     if(resp != STATUS_SUCCESS && resp != STATUS_MORE_ENTRIES)
       break;

     names[idx] = {};
     names[idx]["rid"] = get_dword(blob:rep, pos:28);

     string_len = get_dword(blob:rep, pos:68);
     if (session_is_unicode() == 1)
       string_len *= 2;

     pos = 72;
     names[idx]["name"] = get_string2(blob:rep, pos:pos, len: string_len);

     pos += string_len;
     if(pos >= strlen(rep) + 2)
       break;

     string_len = get_word(blob:rep, pos:pos);
     if (session_is_unicode() == 1)
       string_len *= 2;
     pos += 2;

     if(string_len > 0 && pos < strlen(rep) + 4)
     {
       pos += 6;
       string_len = get_dword(blob:rep, pos:pos);
       if (session_is_unicode() == 1)
         string_len *= 2;

       pos += 4;
       names[idx]["desc"] = get_string2(blob:rep, pos:pos, len:string_len);
       pos += string_len;
     }
     else
     {
       names[idx]["desc"] = '';
     }

     if(pos >= strlen(rep) + 2)
       break;

     string_len = get_word(blob:rep, pos:pos);
     if (session_is_unicode() == 1)
       string_len *= 2;
     pos += 2;

     if(string_len > 0 && pos < strlen(rep) + 4)
     {
       pos += 6;
       string_len = get_dword(blob:rep, pos:pos);
       if (session_is_unicode() == 1)
         string_len *= 2;

       pos += 4;
       names[idx]["full_name"] = get_string2(blob:rep, pos:pos, len:string_len);
     }
     else
     {
       names[idx]["full_name"] = '';
     }

     idx += 1;
   }

   result["status"] = resp;
   result["names"] = names;

   return result;
}

##
# Return user account aliases
#
# @param [handle:int] An SMB handle of a domain.
# @param [sid:int] Security descriptor of the user.
# @param [rids:array] Array of RIDs of groups the user belongs to.
# @param [urid:int] RID of the user in the domain.
#
# @return An array of account aliases on success, NULL otherwise.
##

function SamGetAliasMemberShip (handle, sid, rids, urid)
{
 local_var data, resp, rep, ret, i, tmp_sid, count, num_sid, ref_id, rid, pos, num_id;

 tmp_sid = sid[0] + raw_byte(b:ord(sid[1]) + 1) + substr (sid, 2, strlen(sid)-1);
 count = ord(sid[1]) + 1;

 num_id = max_index(rids) + 1;

 data = handle[0]       +
        raw_dword (d:num_id)      + # count
        raw_dword (d:0x00146668)  + # ref_id
        raw_dword (d:num_id)      ; # max count

 ref_id = 0x001466a8;

 for (i=0; i<num_id; i++)
 {
  data += raw_dword (d:ref_id);
  ref_id += 0x28;
 }

 # we add user rid first
 data += raw_dword (d:count) + tmp_sid + raw_dword (d:urid);

 # and group rids
 foreach rid (rids)
   data += raw_dword (d:count) + tmp_sid + raw_dword (d:rid);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETALIASM, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 12))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 count = get_dword (blob:rep, pos:0);
 if (count == 0)
   return NULL;

 ret = NULL;
 pos = 12;

 if (strlen(rep) < pos + count*4 + 4)
   return NULL;

 for (i=0; i<count; i++)
 {
  ret[i] = get_dword(blob:rep, pos:pos);
  pos += 4;
 }

 return ret;
}


##
# Closes an SMB handle.
#
# @param [handle:int] An SMB handle.
# @return TRUE if success, NULL otherwise.
##

function SamCloseHandle (handle)
{
 local_var data, rep, code, ret;

 code = NULL;

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMCLOSEHANDLE, data:handle[0]);
 if (data)
 {
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (rep && (strlen (rep) == 24))
  { 
   # NULL handle (useless) + code
   # Return code
   code = get_dword (blob:rep, pos:20);
  }
 }

 if (handle[2] == 1)
   ret = smb_close (fid:handle[1]);

 if (isnull (code) || (code != STATUS_SUCCESS) || (ret != 1))
   return NULL;

 return 1;
}

