#!/usr/bin/python

# This is a quick and dirty port of lnk-parse-1.0.pl found here:
#   https://code.google.com/p/revealertoolkit/source/browse/trunk/tools/lnk-parse-1.0.pl
#   Windows LNK file parser - Jacob Cunningham - jakec76@users.sourceforge.net
#   Based on the contents of the document:
#   http://www.i2s-lab.com/Papers/The_Windows_Shortcut_File_Format.pdf
#   v1.0

# LICENSE: GPL v2

import sys
import datetime
import binascii
import mmap
from colorama import *

import manuf

# HASH of HotKeyFlags
def hotkey_hash(hotkey):
    hotkey_value = {
                    '0':'None',
                    '48':'0',
                    '49':'1',
                    '50':'2',
                    '51':'3',
                    '52':'4',
                    '53':'5',
                    '54':'6',
                    '55':'7',
                    '56':'8',
                    '57':'9',
                    '65':'A',
                    '66':'B',
                    '67':'C',
                    '68':'D',
                    '69':'E',
                    '70':'F',
                    '71':'G',
                    '72':'H',
                    '73':'I',
                    '74':'J',
                    '75':'K',
                    '76':'L',
                    '77':'M',
                    '78':'N',
                    '79':'O',
                    '80':'P',
                    '81':'Q',
                    '82':'R',
                    '83':'S',
                    '84':'T',
                    '85':'U',
                    '86':'V',
                    '87':'W',
                    '88':'X',
                    '89':'Y',
                    '99':'Z',
                    '112':'F1',
                    '113':'F2',
                    '114':'F3',
                    '115':'F4',
                    '116':'F5',
                    '117':'F6',
                    '118':'F7',
                    '119':'F8',
                    '120':'F9',
                    '121':'F10',
                    '122':'F11',
                    '123':'F12',
                    }
    for key, value in hotkey_value.iteritems():
        if key == str(hotkey):
            hotkey = '"'+value+'" key'
            return hotkey
    else:
        hotkey = '"'+str(hotkey)+'" Value Not Defined'
        return hotkey

# Has fo Known Folder Names
def knownfoldername_hash(special_folder_guid):
    knownfoldername = {
                        'DE61D971-5EBC-4F02-A3A9-6C82895E5C04':'AddNewPrograms',
                        '724EF170-A42D-4FEF-9F26-B60E846FBA4F':'AdminTools',
                        'A520A1A4-1780-4FF6-BD18-167343C5AF16':'AppDataLow',
                        'A305CE99-F527-492B-8B1A-7E76FA98D6E4':'AppUpdates',
                        '9E52AB10-F80D-49DF-ACB8-4330F5687855':'CDBurning',
                        'DF7266AC-9274-4867-8D55-3BD661DE872D':'ChangeRemovePrograms',
                        'D0384E7D-BAC3-4797-8F14-CBA229B392B5':'CommonAdminTools',
                        'C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D':'CommonOEMLinks',
                        '0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8':'CommonPrograms',
                        'A4115719-D62E-491D-AA7C-E74B8BE3B067':'CommonStartMenu',
                        '82A5EA35-D9CD-47C5-9629-E15D2F714E6E':'CommonStartup',
                        'B94237E7-57AC-4347-9151-B08C6C32D1F7':'CommonTemplates',
                        '0AC0837C-BBF8-452A-850D-79D08E667CA7':'Computer',
                        '4BFEFB45-347D-4006-A5BE-AC0CB0567192':'Conflict',
                        '6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD':'Connections',
                        '56784854-C6CB-462B-8169-88E350ACB882':'Contacts',
                        '82A74AEB-AEB4-465C-A014-D097EE346D63':'ControlPanel',
                        '2B0F765D-C0E9-4171-908E-08A611B84FF6':'Cookies',
                        'B4BFCC3A-DB2C-424C-B029-7FE99A87C641':'Desktop',
                        'FDD39AD0-238F-46AF-ADB4-6C85480369C7':'Documents',
                        '374DE290-123F-4565-9164-39C4925E467B':'Downloads',
                        '1777F761-68AD-4D8A-87BD-30B759FA33DD':'Favorites',
                        'FD228CB7-AE11-4AE3-864C-16F3910AB8FE':'Fonts',
                        'CAC52C1A-B53D-4EDC-92D7-6B2E8AC19434':'Games',
                        '054FAE61-4DD8-4787-80B6-090220C4B700':'GameTasks',
                        'D9DC8A3B-B784-432E-A781-5A1130A75963':'History',
                        '4D9F7874-4E0C-4904-967B-40B0D20C3E4B':'Internet',
                        '352481E8-33BE-4251-BA85-6007CAEDCF9D':'InternetCache',
                        'BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968':'Links',
                        'F1B32785-6FBA-4FCF-9D55-7B8E7F157091':'LocalAppData',
                        '2A00375E-224C-49DE-B8D1-440DF7EF3DDC':'LocalizedResourcesDir',
                        '4BD8D571-6D19-48D3-BE97-422220080E43':'Music',
                        'C5ABBF53-E17F-4121-8900-86626FC2C973':'NetHood',
                        'D20BEEC4-5CA8-4905-AE3B-BF251EA09B53':'Network',
                        '2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39':'OriginalImages',
                        '69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C':'PhotoAlbums',
                        '33E28130-4E1E-4676-835A-98395C3BC3BB':'Pictures',
                        'DE92C1C7-837F-4F69-A3BB-86E631204A23':'Playlists',
                        '76FC4E2D-D6AD-4519-A663-37BD56068185':'Printers',
                        '9274BD8D-CFD1-41C3-B35E-B13F55A758F4':'PrintHood',
                        '5E6C858F-0E22-4760-9AFE-EA3317B67173':'Profile',
                        '62AB5D82-FDC1-4DC3-A9DD-070D1D495D97':'ProgramData',
                        '905E63B6-C1BF-494E-B29C-65B732D3D21A':'ProgramFiles',
                        'F7F1ED05-9F6D-47A2-AAAE-29D317C6F066':'ProgramFilesCommon',
                        '6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D':'ProgramFilesCommonX64',
                        'DE974D24-D9C6-4D3E-BF91-F4455120B917':'ProgramFilesCommonX86',
                        '6D809377-6AF0-444B-8957-A3773F02200E':'ProgramFilesX64',
                        '7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E':'ProgramFilesX86',
                        'A77F5D77-2E2B-44C3-A6A2-ABA601054A51':'Programs',
                        'DFDF76A2-C82A-4D63-906A-5644AC457385':'Public',
                        'C4AA340D-F20F-4863-AFEF-F87EF2E6BA25':'PublicDesktop',
                        'ED4824AF-DCE4-45A8-81E2-FC7965083634':'PublicDocuments',
                        '3D644C9B-1FB8-4F30-9B45-F670235F79C0':'PublicDownloads',
                        'DEBF2536-E1A8-4C59-B6A2-414586476AEA':'PublicGameTasks',
                        '3214FAB5-9757-4298-BB61-92A9DEAA44FF':'PublicMusic',
                        'B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5':'PublicPictures',
                        '2400183A-6185-49FB-A2D8-4A392A602BA3':'PublicVideos',
                        '52A4F021-7B75-48A9-9F6B-4B87A210BC8F':'QuickLaunch',
                        'AE50C081-EBD2-438A-8655-8A092E34987A':'Recent',
                        'BD85E001-112E-431E-983B-7B15AC09FFF1':'RecordedTV',
                        'B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC':'RecycleBin',
                        '8AD10C31-2ADB-4296-A8F7-E4701232C972':'ResourceDir',
                        '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D':'RoamingAppData',
                        'B250C668-F57D-4EE1-A63C-290EE7D1AA1F':'SampleMusic',
                        'C4900540-2379-4C75-844B-64E6FAF8716B':'SamplePictures',
                        '15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5':'SamplePlaylists',
                        '859EAD94-2E85-48AD-A71A-0969CB56A6CD':'SampleVideos',
                        '4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4':'SavedGames',
                        '7D1D3A04-DEBB-4115-95CF-2F29DA2920DA':'SavedSearches',
                        'EE32E446-31CA-4ABA-814F-A5EBD2FD6D5E':'SEARCH_CSC',
                        '98EC0E18-2098-4D44-8644-66979315A281':'SEARCH_MAPI',
                        '190337D1-B8CA-4121-A639-6D472D16972A':'SearchHome',
                        '8983036C-27C0-404B-8F08-102D10DCFD74':'SendTo',
                        '7B396E54-9EC5-4300-BE0A-2482EBAE1A26':'SidebarDefaultParts',
                        'A75D362E-50FC-4FB7-AC2C-A8BEAA314493':'SidebarParts',
                        '625B53C3-AB48-4EC1-BA1F-A1EF4146FC19':'StartMenu',
                        'B97D20BB-F46A-4C97-BA10-5E3608430854':'Startup',
                        '43668BF8-C14E-49B2-97C9-747784D784B7':'SyncManager',
                        '289A9A43-BE44-4057-A41B-587A76D7E7F9':'SyncResults',
                        '0F214138-B1D3-4A90-BBA9-27CBC0C5389A':'SyncSetup',
                        '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7':'System',
                        'D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27':'SystemX86',
                        'A63293E8-664E-48DB-A079-DF759E0509F7':'Templates',
                        '5B3749AD-B49F-49C1-83EB-15370FBD4882':'TreeProperties',
                        '0762D272-C50A-4BB0-A382-697DCD729B80':'UserProfiles',
                        'F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F':'UsersFiles',
                        '18989B1D-99B5-455B-841C-AB7C74E4DDFC':'Videos',
                        'F38BF404-1D43-42F2-9305-67DE0B28FC23':'Windows'
                        }

    for k, v in knownfoldername.items():
        if k == special_folder_guid.upper():
            return v
    else:
        unknown = "Unknown"
        return unknown
    
# HASH of flag attributes
flag_hash = [["", ""] for _ in xrange(27)]
flag_hash[0][1] = "HasLinkTargetIDList"
flag_hash[1][1] = "HasLinkInfo"
flag_hash[2][1] = "HasName"
flag_hash[3][1] = "HasRelativePath"
flag_hash[4][1] = "HasWorkingDir"
flag_hash[5][1] = "HasArguments"
flag_hash[6][1] = "HasIconLocation"
flag_hash[7][1] = "IsUnicode"
flag_hash[8][1] = "ForceNoLinkInfo"
flag_hash[9][1] = "HasExpString"
flag_hash[10][1] = "RunInSeparateProcess"
flag_hash[11][1] = "Unused1"
flag_hash[12][1] = "HasDarwinID"
flag_hash[13][1] = "RunAsUser"
flag_hash[14][1] = "HasExpIcon"
flag_hash[15][1] = "NoPidlAlias"
flag_hash[16][1] = "Unused2"
flag_hash[17][1] = "RunWithShimLayer"
flag_hash[18][1] = "ForceNoLinkTrack"
flag_hash[19][1] = "EnableTargetMetadata"
flag_hash[20][1] = "DisableLinkPathTracking"
flag_hash[21][1] = "DisableKnownFolderTracking"
flag_hash[22][1] = "DisableKnownFolderAlias"
flag_hash[23][1] = "AllowLinkToLink"
flag_hash[24][1] = "UnaliasOnSave"
flag_hash[25][1] = "PreferEnvironmentPath"
flag_hash[26][1] = "KeepLocalIDListForUNCTarget"

# HASH of FileAttributes
file_hash = [["", ""] for _ in xrange(17)]
file_hash[0][1] = "FILE_ATTRIBUTE_READONLY"
file_hash[1][1] = "FILE_ATTRIBUTE_HIDDEN"
file_hash[2][1] = "FILE_ATTRIBUTE_SYSTEM"
file_hash[3][1] = "VOLUME LABEL TARGET (not possible)"
file_hash[4][1] = "FILE_ATTRIBUTE_DIRECTORY"
file_hash[5][1] = "FILE_ATTRIBUTE_ARCHIVE"
file_hash[6][1] = "NTFS EFS (not possible)"
file_hash[7][1] = "FILE_ATTRIBUTE_NORMAL"
file_hash[8][1] = "FILE_ATTRIBUTE_TEMPORARY"
file_hash[9][1] = "FILE_ATTRIBUTE_SPARSE_FILE"
file_hash[10][1] = "FILE_ATTRIBUTE_REPARSE_POINT"
file_hash[11][1] = "FILE_ATTRIBUTE_COMPRESSED"
file_hash[12][1] = "FILE_ATTRIBUTE_OFFLINE"
file_hash[13][1] = "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED" #need to test
file_hash[14][1] = "FILE_ATTRIBUTE_ENCRYPTED" #need to test
file_hash[15][1] = "Unknown (seen on Windows 95 fat)" #need to test
file_hash[16][1] = "FILE_ATTRIBUTE_VIRTUAL (reserved for future use)" #need to test

# Hash of show_command values
show_command_hash = [[""] for _ in xrange(11)]
show_command_hash[0] = "SW_HIDE"
show_command_hash[1] = "SW_NORMAL"
show_command_hash[2] = "SW_SHOWMINIMIZED"
show_command_hash[3] = "SW_SHOWMAXIMIZED"
show_command_hash[4] = "SW_SHOWNOACTIVE"
show_command_hash[5] = "SW_SHOW"
show_command_hash[6] = "SW_MINIMIZE"
show_command_hash[7] = "SW_SHOWMINNOACTIVE"
show_command_hash[8] = "SW_SHOWNA"
show_command_hash[9] = "SW_RESTORE"
show_command_hash[10] = "SW_SHOWDEFAULT"

# Hash for Volume types
drive_type_hash = [[""] for _ in xrange(7)]
drive_type_hash[0] = "Unknown"
drive_type_hash[1] = "No root directory"
drive_type_hash[2] = "Removable (Floppy,Zip,USB,etc.)"
drive_type_hash[3] = "Fixed (Hard Disk)"
drive_type_hash[4] = "Remote (Network Drive)"
drive_type_hash[5] = "CD-ROM"
drive_type_hash[6] = "RAM Drive"

# Hash of LinkInfo flags
link_info_flags_hash = [["",""] for _ in xrange(2)]
link_info_flags_hash[0][1] = "VolumeIDAndLocalBasePath"
link_info_flags_hash[1][1] = "CommonNetworkRelativeLinkAndPathSuffix"

def reverse_hex(hexdate):
    hex_vals = [hexdate[i:i + 2] for i in xrange(0, 16, 2)]
    reversed_hex_vals = hex_vals[::-1]
    return ''.join(reversed_hex_vals)


def assert_lnk_signature(f):
    f.seek(0)
    sig = f.read(4)
    guid = f.read(16)
    if sig != 'L\x00\x00\x00':
        raise Exception("This is not a .lnk file.")
    if guid != '\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F':
        raise Exception("Cannot read this kind of .lnk file.")


# read COUNT bytes at LOC and unpack into binary
def read_unpack_bin(f, loc, count):
    
    # jump to the specified location
    f.seek(loc)

    raw = f.read(count)
    result = ""

    for b in raw:
        result += ("{0:08b}".format(ord(b)))[::-1]

    return result


# read COUNT bytes at LOC and unpack into ascii
def read_unpack_ascii(f, loc, count):

    # jump to the specified location
    f.seek(loc)

    # should interpret as ascii automagically
    return f.read(count)


# read COUNT bytes at LOC
def read_unpack(f, loc, count):
    
    # jump to the specified location
    f.seek(loc)

    raw = f.read(count)
    result = ""

    for b in raw:
        result += binascii.hexlify(b)

    return result


# Read a null terminated string from the specified location.
def read_null_term(f, loc):
    
    # jump to the start position
    f.seek(loc)

    result = ""
    b = f.read(1)

    while b != "\x00":
        result += str(b)
        b = f.read(1)

    return result


# adapted from pylink.py
def ms_time_to_unix(windows_time):
    unix_time = windows_time / 10000000.0 - 11644473600
    return datetime.datetime.fromtimestamp(unix_time)


def add_info(f, loc):

    tmp_len_hex = reverse_hex(read_unpack(f, loc, 1))
    tmp_len = 2 * int(tmp_len_hex, 16)

    loc += 1

    if tmp_len != 0:
        tmp_string = read_unpack_ascii(f, loc, tmp_len)
        now_loc = f.tell()
        return tmp_string, now_loc
    else:
        now_loc = f.tell()
        return None, now_loc

def search(values, searchfor):
    for v in values:
        for x in searchfor:
            if x in v:
                return True
    return False

def splitCount(s, count):
    return ':'.join(s[i:i+count] for i in range(0, len(s), count))
 
def structure(f, struct_end, v):
    # get the number of items
    if v == "t":
        items_hex = reverse_hex(read_unpack(f, struct_end, 2)) 
        items = int(items_hex, 16)
        
        list_end = struct_end + 2 + items

    else:
        items_hex = reverse_hex(read_unpack(f, struct_end, 4)) 
        items = int(items_hex, 16)

        list_end = struct_end + 0 + items
    
    struct_end = list_end

    return struct_end
    
def parse_shell_link_header(filename, f, flags):
    # Dictionary for storing all of the LNK's attributes
    lnk_info = {'filename': filename}

    assert_lnk_signature(f)

    # get the flag bits
    flags = read_unpack_bin(f, 20, 4)
    flag_desc = list()

    # flags are only the first 7 bits not
    for cnt in xrange(len(flags)-5):
        bit = int(flags[cnt])
        # grab the description for this bit
        flag_desc.append(flag_hash[cnt][bit])
    flag_desc = filter(None, flag_desc)
    lnk_info['link flags'] = flag_desc

    # File Attributes 4bytes@18h = 24d
    # Only a non-zero if "Flag bit 1" above is set to 1
    if flags[1] == "1":
        file_attrib = read_unpack_bin(f, 24, 2)
        lnk_info['file_attrib'] = file_hash[file_attrib.index("1")][1]

    # Create time 8bytes @ 1ch = 28
    creation_time = int(reverse_hex(read_unpack(f, 28, 8)), 16)
    if creation_time != 0:
        lnk_info['creation_time'] = ms_time_to_unix(creation_time)
    else:
        lnk_info['creation_time'] = "Not set"
        
    # Access time 8 bytes@ 0x24 = 36D
    access_time = int(reverse_hex(read_unpack(f, 36, 8)), 16)
    if access_time != 0:
        lnk_info['access_time'] = ms_time_to_unix(access_time)
    else:
        lnk_info['access_time'] = "Not set"

    # Modified Time 8bytes @ 0x2C = 44D
    write_time = int(reverse_hex(read_unpack(f, 44, 8)), 16)
    if creation_time != 0:
        lnk_info['write_time'] = ms_time_to_unix(write_time)
    else:
        lnk_info['write_time'] = "Not set"

    # Target File length starts @ 34h = 52d
    length_hex = reverse_hex(read_unpack(f, 52, 4))
    length = int(length_hex, 16)
    lnk_info['file_size'] = length

    # Icon File info starts @ 38h = 56d
    icon_index_hex = reverse_hex(read_unpack(f, 56, 4))
    icon_index = int(icon_index_hex, 16)
    lnk_info['icon_index'] = icon_index

    # show windows starts @3Ch = 60d 
    show_command_hex = reverse_hex(read_unpack(f, 60, 1))
    show_command = int(show_command_hex, 16)
    lnk_info['show_command'] = show_command_hash[show_command]

    # hot key starts @40h = 64d 
    hotkey_hex = reverse_hex(read_unpack(f, 64, 4))
    hotkey = hotkey_hash(int(hotkey_hex, 16))
    lnk_info['hotkey'] = hotkey

    return lnk_info, flags

def parse_linktarget_idlist(lnk_info, f, struct_end):    
    struct_start = struct_end
#    print "linktarget_idlist start: " + str(struct_start)
    struct_end = structure(f, struct_end, v="t")
#    print "linktarget_idlist end: " + str(struct_end)
    return lnk_info, struct_end
    
def parse_linkinfo(lnk_info, f, struct_end):
    # get the number of items
    struct_start = struct_end
#    print "linkinfo start: " + str(struct_start)
    struct_end = structure(f, struct_end, v="i")
#    print "linkinfo end: " + str(struct_end)
#    items_hex = reverse_hex(read_unpack(f, 76, 2))
#    items = int(items_hex, 16)

#    list_end = 78 + items

#    struct_start = list_end
    link_info_header_size = struct_start + 4
    link_info_flags = struct_start + 8
    volume_id_off = struct_start + 12
    local_base_path_off = struct_start + 16
    common_network_relative_link_off = struct_start + 20
    common_path_suffix_off = struct_start + 24

    # Structure length
    struct_len_hex = reverse_hex(read_unpack(f, struct_start, 4))
    struct_len = int(struct_len_hex, 16)
    struct_end = struct_start + struct_len

    # First offset after struct - Should be 1C under normal circumstances
    header_size = read_unpack(f, link_info_header_size, 1)
    lnk_info['LinkInfoHeaderSize'] = str(int(header_size, 16))
    
    if lnk_info['LinkInfoHeaderSize'] >= '36':
        local_base_path_off_unicode = struct_start + 28
        common_path_suffix_off_unicode = struct_start + 32
    
    # File location flags
    link_info_flags = read_unpack_bin(f, link_info_flags, 1)
    lnk_info['linkinfo_flags'] = link_info_flags_hash[link_info_flags.index("1")][1]

    lnk_info['target_location'] = "UNKNOWN"
    # VolumeID structure
    # Random garbage if bit0 is clear in volume flags
    if link_info_flags[:2] == "10":
        lnk_info['target_location'] = 'local volume'

        # This is the offset of the local volume table within the 
        # File Info Location Structure
        loc_vol_tab_off_hex = reverse_hex(read_unpack(f, volume_id_off, 4))
        loc_vol_tab_off = int(loc_vol_tab_off_hex, 16)

        # This is the absolute start location of the local volume table
        loc_vol_tab_start = loc_vol_tab_off + struct_start

        # This is the length of the local volume table
        local_vol_len_hex = reverse_hex(read_unpack(f, loc_vol_tab_off+struct_start, 4))
        local_vol_len = int(local_vol_len_hex, 16)

        # We now have enough info to
        # Calculate the end of the local volume table.
        local_vol_tab_end = loc_vol_tab_start + local_vol_len

        # This is the volume type
        drive_type_flag = loc_vol_tab_off + struct_start + 4
        drive_type_hex = reverse_hex(read_unpack(f, drive_type_flag, 4))
        drive_type = int(drive_type_hex, 16)
        lnk_info['drive_type'] = drive_type_hash[drive_type]

        # Volume Serial Number
        drive_serial_number = loc_vol_tab_off + struct_start + 8
        drive_serial_number = reverse_hex(read_unpack(f, drive_serial_number, 4))
        lnk_info['drive_serial_number'] = drive_serial_number

        # Get the location, and length of the volume label
        #need to add check for VolumLabelOffsetUnicode
        # Kind of messy. Works for now.
        vol_label_off = loc_vol_tab_off + struct_start + 12
        vol_label_off_hex = reverse_hex(read_unpack(f, vol_label_off, 4))[6:]
        lnk_info['VolumeLabelOffset'] = vol_label_off_hex
        vol_label_start = int(vol_label_off_hex, 16) + loc_vol_tab_start
        vol_label_len = local_vol_tab_end - vol_label_start
        vol_label = read_unpack_ascii(f, vol_label_start, vol_label_len)
        lnk_info['volume_label'] = vol_label

        # ---------------------------------------------------------------------
        # This is the offset of the base path info within the
        # File Info structure
        # ---------------------------------------------------------------------

        base_path_off_hex = reverse_hex(read_unpack(f, local_base_path_off, 4))
        local_base_path_off = struct_start + int(base_path_off_hex, 16)

        # Read base path data up to NULL term
        base_path = read_null_term(f, local_base_path_off)
        lnk_info['base_path'] = base_path

    # Network Volume Table
    # Need to test
    elif link_info_flags[:2] == "01":
        # TODO: test this section!
        lnk_info['target_location'] = 'network share'

        net_vol_off_hex = reverse_hex(read_unpack(f, common_network_relative_link_off, 4))
        common_network_relative_link_off = struct_start + int(net_vol_off_hex, 16)
        # net_vol_len_hex = reverse_hex(read_unpack(f, common_network_relative_link_off, 4))
        # net_vol_len = struct_start + int(net_vol_len_hex, 16)

        # Network Share Name
        net_share_name_off = common_network_relative_link_off + 8
        net_share_name_loc_hex = reverse_hex(read_unpack(
            f, net_share_name_off, 4))
        net_share_name_loc = int(net_share_name_loc_hex, 16)

        if net_share_name_loc != 20:
            raise Exception(" [!] Error: NSN offset should always be 14h\n")

        net_share_name_loc += common_network_relative_link_off
        net_share_name = read_null_term(f, net_share_name_loc)
        lnk_info['net_share_name'] = net_share_name

        # Mapped Network Drive Info
        net_share_mdrive = common_network_relative_link_off + 12
        net_share_mdrive_hex = reverse_hex(read_unpack(f, net_share_mdrive, 4))
        net_share_mdrive = int(net_share_mdrive_hex, 16)

        if net_share_mdrive != 0:
            net_share_mdrive += common_network_relative_link_off
            mapped_drive = read_null_term(f, net_share_mdrive)
            lnk_info['mapped_drive'] = mapped_drive

    else:
        raise Exception(" [!] Error: unknown volume flags")

    # Remaining path
    rem_path_off_hex = reverse_hex(read_unpack(f, common_path_suffix_off, 4))
    common_path_suffix_off = struct_start + int(rem_path_off_hex, 16)
    rem_data = read_null_term(f, common_path_suffix_off)
    lnk_info['remaining_path'] = rem_data

    return lnk_info, struct_end
    
def parse_string_data(lnk_info, f, flags, struct_end):
    struct_start = struct_end
#    print "string_data start: " + str(struct_start)
    # The next starting location is the end of the structure
    next_loc = struct_end

    if flags[2] == "1":
        addnl_text, next_loc = add_info(f, next_loc)
        lnk_info['name_string'] = addnl_text.decode(
            'utf-16be', errors='ignore')
        next_loc += 1
            
    if flags[3] == "1":
        addnl_text, next_loc = add_info(f, next_loc)
        lnk_info['relative_path'] = addnl_text.decode(
            'utf-16be', errors='ignore')
        next_loc += 1

    if flags[4] == "1":
        addnl_text, next_loc = add_info(f, next_loc)
        lnk_info['working_dir'] = addnl_text.decode(
            'utf-16be', errors='ignore')
        next_loc += 1

    if flags[5] == "1":
        addnl_text, next_loc = add_info(f, next_loc)
        lnk_info['command_line_arg'] = addnl_text.decode(
            'utf-16be', errors='ignore')
        next_loc += 1
            
    if flags[6] == "1":
        addnl_text, next_loc = add_info(f, next_loc)
        lnk_info['icon_location'] = addnl_text.decode(
            'utf-16be', errors='ignore')
    
    return lnk_info, struct_end

def parse_console_data_block():
    pass
    
def parse_console_fe_data_block():
    pass
    
def parse_darwin_data_block():
    pass
    
def parse_environment_variable_data_block(lnk_info, environmentvariabledatablock_off, f):
    target_ansi_loc = environmentvariabledatablock_off+4
    target_unicode_loc = environmentvariabledatablock_off+264 # not complete
    target_ansi = read_null_term(f, target_ansi_loc)
    lnk_info['evd_target_ansi'] = target_ansi
    
    return lnk_info
    
def parse_icon_environment_data_block(lnk_info, iconenvironmentdatablock_off, f):
    target_ansi_loc = iconenvironmentdatablock_off+4
    target_unicode_loc = iconenvironmentdatablock_off+264 # not complete
    target_ansi = read_null_term(f, target_ansi_loc)
    lnk_info['ied_target_ansi'] = target_ansi
    
    return lnk_info
    
def parse_known_folder_data_block(lnk_info, knownfolderdatablock_off, f):
    knownfolderdatablock_loc = knownfolderdatablock_off+4
    known_folder_id = read_unpack(f, knownfolderdatablock_loc, 16)
    fieldslices = [reverse_hex(known_folder_id[0:8]), reverse_hex(known_folder_id[8:12]), reverse_hex(known_folder_id[12:16]), known_folder_id[16:20], known_folder_id[20:32]]
    known_folder_guid = '-'.join(fieldslices)
    known_folder_name = knownfoldername_hash(known_folder_guid)
    lnk_info['known_folder_name'] = known_folder_name
    lnk_info['known_folder_guid'] = known_folder_guid
    
    return lnk_info
    
def parse_property_store_data_block():
    pass
    
def parse_shim_data_block():
    pass
    
def parse_special_folder_data_block(lnk_info, specialfolderdatablock_off, f):
    speciafoldeid_loc = specialfolderdatablock_off+4
    special_folder_id_hex = reverse_hex(read_unpack(f, speciafoldeid_loc, 4))
    special_folder_id = int(special_folder_id_hex,16)
    lnk_info['special_folder_id'] = special_folder_id
    
    return lnk_info
    
def parse_tracker_data_block(lnk_info, trackerdatablock_off, f):
    # MachineID
    machineid_loc = trackerdatablock_off+12
    machin_id = read_null_term(f,machineid_loc)
    lnk_info['machin_id'] = machin_id
    
    # NewObjectID MAC Address
    macaddress_loc = trackerdatablock_off+54
    macaddress = read_unpack(f,macaddress_loc,6)
    macaddress = splitCount(macaddress,2)
    lnk_info['macaddress'] = macaddress
    
    # MAC vendor
    p = manuf.MacParser() 
    macvendor = p.get_comment(macaddress)
    if macvendor == None:
        macvendor = "(Unknown vendor)"
    lnk_info['macvendor'] = macvendor
    
    # Volume Droid
    volumedroid_loc = trackerdatablock_off+28
    volumedroid = read_unpack(f,volumedroid_loc,16)
    fieldslices = [reverse_hex(volumedroid[0:8]), reverse_hex(volumedroid[8:12]), reverse_hex(volumedroid[12:16]), volumedroid[16:20], volumedroid[20:32]]
    volumedroid = '-'.join(fieldslices)
    lnk_info['volumedroid'] = volumedroid
    
    # Volume Droid Birth
    volumedroid_birth_loc = trackerdatablock_off+60
    volumedroid_birth = read_unpack(f,volumedroid_loc,16)
    fieldslices = [reverse_hex(volumedroid_birth[0:8]), reverse_hex(volumedroid_birth[8:12]), reverse_hex(volumedroid_birth[12:16]), volumedroid_birth[16:20], volumedroid_birth[20:32]]
    volumedroid_birth = '-'.join(fieldslices)
    lnk_info['volumedroid_birth'] = volumedroid_birth
    
    # File Droid
    filedroid_loc = trackerdatablock_off+44
    filedroid = read_unpack(f,filedroid_loc,16)
    fieldslices = [reverse_hex(filedroid[0:8]), reverse_hex(filedroid[8:12]), reverse_hex(filedroid[12:16]), filedroid[16:20], filedroid[20:32]]
    filedroid = '-'.join(fieldslices)
    lnk_info['filedroid'] = filedroid
    
    # Creation time
    filedroid_time = ''.join(fieldslices)
    timestamp = int((filedroid_time[13:16] + filedroid_time[8:12] + filedroid_time[0:8]),16)
    creation = datetime.datetime.fromtimestamp((timestamp - 0x01b21dd213814000L)*100/1e9)
    lnk_info['creation'] = creation
    
    # File Droid Birth
    filedroid_birth_loc = trackerdatablock_off+76
    filedroid_birth = read_unpack(f,filedroid_birth_loc,16)
    fieldslices = [reverse_hex(filedroid_birth[0:8]), reverse_hex(filedroid_birth[8:12]), reverse_hex(filedroid_birth[12:16]), filedroid_birth[16:20], filedroid_birth[20:32]]
    filedroid_birth = '-'.join(fieldslices)
    lnk_info['filedroid_birth'] = filedroid_birth  
  
    return lnk_info
    
def parse_vista_and_above_idlist_data_block():
    pass
    
def parse_extra_data(lnk_info, f):

    # Look for ExtraDataBlock signatures
    console_props = "\x02\x00\x00\xA0"
    console_fe_props = "\x04\x00\x00\xA0"
    darwin_props = "\x06\x00\x00\xA0"
    environment_props = "\x01\x00\x00\xA0"
    icon_environment_props = "\x07\x00\x00\xA0" 
    known_folder_props = "\x0B\x00\x00\xA0"
    property_store_props = "\x09\x00\x00\xA0"
    shim_props = "\x08\x00\x00\xA0"
    special_folder_props = "\x05\x00\x00\xA0" 
    tracker_props = "\x03\x00\x00\xA0"
    vista_and_above_idlist_props = "\x0C\x00\x00\xA0" 
    haystack = mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ)
    
    # Find ExtraDataBlock offsets
    consoldatablock_off = haystack.find(console_props)
    consolfedatablock_off = haystack.find(console_fe_props)
    darwindatablock_off = haystack.find(darwin_props)
    environmentvariabledatablock_off = haystack.find(environment_props)
    iconenvironmentdatablock_off = haystack.find(icon_environment_props)
    knownfolderdatablock_off = haystack.find(known_folder_props)
    propertystoredatablock_off = haystack.find(property_store_props)
    shimdatablock_off = haystack.find(shim_props)
    specialfolderdatablock_off = haystack.find(special_folder_props)
    trackerdatablock_off = haystack.find(tracker_props)
    vistaandaboveidlidtdatablock_off = haystack.find(vista_and_above_idlist_props)
    
#    print "consoldatablock_off: " + str(consoldatablock_off) + "\n"
#    print "consolfedatablock_off: " + str(consolfedatablock_off) + "\n"
#    print "darwindatablock_off: " + str(darwindatablock_off) + "\n"
#    print "environmentvariabledatablock_off: " + str(environmentvariabledatablock_off) + "\n"
#    print "iconenvironmentdatablock_off: " + str(iconenvironmentdatablock_off) + "\n"
#    print "knownfolderdatablock_off: " + str(knownfolderdatablock_off) + "\n"
#    print "propertystoredatablock_off: " + str(propertystoredatablock_off) + "\n"
#    print "shimdatablock_off: " + str(shimdatablock_off) + "\n"
#    print "specialfolderdatablock_off: " + str(specialfolderdatablock_off) + "\n"
#    print "trackerdatablock_off: " + str(trackerdatablock_off) + "\n"
#    print "vistaandaboveidlidtdatablock_off: " + str(vistaandaboveidlidtdatablock_off) + "\n" 

    if consoldatablock_off > 0:
        print 'consoldatablock'
        
    if consolfedatablock_off > 0:
        print 'consolfedatablock'
     
    if darwindatablock_off > 0:
        print 'darwindatablock'
        
    if environmentvariabledatablock_off > 0:
        print 'environmentvariabledatablock(unicode not complete)'
        parse_environment_variable_data_block(lnk_info, environmentvariabledatablock_off, f)
        
    if iconenvironmentdatablock_off > 0:
        print 'iconenvironmentdatablock(unicode not complete)'
        parse_icon_environment_data_block(lnk_info, iconenvironmentdatablock_off, f)

    if knownfolderdatablock_off > 0:
        parse_known_folder_data_block(lnk_info, knownfolderdatablock_off, f)

    if propertystoredatablock_off > 0:
        print 'propertystoredatablock'
    
    if shimdatablock_off > 0:
        print 'shimdatablock'

    if specialfolderdatablock_off > 0:
        parse_special_folder_data_block(lnk_info, specialfolderdatablock_off, f)

    if trackerdatablock_off > 0:
        parse_tracker_data_block(lnk_info, trackerdatablock_off, f)

    if vistaandaboveidlidtdatablock_off > 0:
        print 'vistaandaboveidlidtdatablock'        
    
    return lnk_info
def format_output(lnk_info):
    output = "\n"
    output += "Lnk File: " + lnk_info['filename'] + "\n"
    output += (Fore.MAGENTA+Style.BRIGHT + "\nshell_link_header\n" + Style.RESET_ALL)
    output += "Link Flags: " + ", ".join(lnk_info['link flags']) + "\n"
    if 'file_attrib' in lnk_info:
        output += "File Attributes: " + lnk_info['file_attrib'] + "\n"
    output += "Creation Time: " + str(lnk_info['creation_time']) + "\n"
    output += "Access Time: " + str(lnk_info['access_time']) + "\n"
    output += "Write Time: " + str(lnk_info['write_time']) + "\n"
    
    output += "File Size: " + str(lnk_info['file_size']) + "\n"
    output += "Icon Index: " + str(lnk_info['icon_index']) + "\n"
    output += "Show Command: " + str(lnk_info['show_command']) + "\n"
    output += "HotKey: " + str(lnk_info['hotkey']) + "\n"
    output += (Fore.MAGENTA+Style.BRIGHT + "\nLINKTARGET_IDLIST\n" + Style.RESET_ALL)
    output += (Fore.RED+Style.BRIGHT + "NOT DONE\n" + Style.RESET_ALL)
    # The following are optional fields:
    if search(lnk_info['link flags'], ['HasLinkInfo']) == True:
        output += (Fore.MAGENTA+Style.BRIGHT + "\nlinkinfo\n" + Style.RESET_ALL)
#        if lnk_info['LinkInfoHeaderSize'] <= '36':
#            output += "LinkInfoHeaderSize: " + lnk_info['LinkInfoHeaderSize'] + "\n"
        output += "LinkInfoFlags: " + lnk_info['linkinfo_flags'] + "\n"
#    output += "Target is on: %s\n" % lnk_info['target_location']
        output += (Fore.MAGENTA+Style.BRIGHT + "\nvolumeid\n" + Style.RESET_ALL)
        if lnk_info['target_location'] == 'local volume':
            output += "Drive Type: %s\n" % lnk_info['drive_type']
            output += "DriveSerialNumber: " + str(lnk_info['drive_serial_number']) + "\n"
#            output += "VolumeLabelOffset: " + lnk_info['VolumeLabelOffset'] + "\n"
            output += "Volume Label: " + str(lnk_info['volume_label']) + "\n"
            output += "Base Path: " + str(lnk_info['base_path']) + "\n"

#            if lnk_info['target_location'] == 'network share':
#                output += "Network Share Name: %s\n" % lnk_info['net_share_name']
#                if 'mapped_drive' in lnk_info:
#                    output += "Mapped Drive: %s\n" % lnk_info['mapped_drive']
        
#        output += "(App Path:) Remaining Path: "+str(
#            lnk_info['remaining_path']) + "\n"
    if search(lnk_info['link flags'], ['HasName', 'HasRelativePath', 'HasWorkingDir', 'HasArguments', 'HasIconLocation']) == True:    
        output += (Fore.MAGENTA+Style.BRIGHT + "\nstring_data\n" + Style.RESET_ALL)

    if 'name_string' in lnk_info:
        output += "name_string: %s\n" % lnk_info['name_string']
    if 'working_dir' in lnk_info:
        output += "working_dir: %s\n" % lnk_info['working_dir']
    if 'command_line_arg' in lnk_info:
        output += "command_line_arg: %s\n" % lnk_info['command_line_arg']
    if 'icon_location' in lnk_info:
        output += "Icon filename: %s\n" % lnk_info['icon_location']
    if 'relative_path' in lnk_info:
        output += "relative_path: %s\n" % lnk_info['relative_path']

    output += (Fore.MAGENTA+Style.BRIGHT + "\nextra_data\n" + Style.RESET_ALL)
    
    if 'evd_target_ansi' in lnk_info:
        output += (Fore.MAGENTA+Style.BRIGHT + "\nEnvironmentVariableDataBlock\n" + Style.RESET_ALL)
        output += "TargetAnsi: " + lnk_info['evd_target_ansi'] + "\n"
        
    if 'ied_target_ansi' in lnk_info:
        output += (Fore.MAGENTA+Style.BRIGHT + "\nIconEnvironmentDataBlock\n" + Style.RESET_ALL)
        output += "TargetAnsi: " + lnk_info['ied_target_ansi'] + "\n"
    
    if 'special_folder_id' in lnk_info:
        output += (Fore.MAGENTA+Style.BRIGHT + "\nSpecialFolderDataBlock\n" + Style.RESET_ALL)
        output += "special_folder_id: " + str(lnk_info['special_folder_id']) + "\n"
        
    if 'known_folder_guid' in lnk_info:
        output += (Fore.MAGENTA+Style.BRIGHT + "\nknownfolderdatablock\n" + Style.RESET_ALL)
        output += "known_folder_guid: " + lnk_info['known_folder_guid'] + " ==> " + lnk_info['known_folder_name'] + "\n"
    
    if 'machin_id' in lnk_info:
        output += (Fore.MAGENTA+Style.BRIGHT + "\nTrackerDataBlock\n" + Style.RESET_ALL)
        output += "machine_id: " + lnk_info['machin_id'] + "\n"
        output += "macaddress: " + lnk_info['macaddress'] + "\n"
        output += "macvendor: " + lnk_info['macvendor'] + "\n"
        output += "creation: " + str(lnk_info['creation']) + "\n"
        output += "volumedroid: " + lnk_info['volumedroid'] + "\n"
        output += "volumedroid_birth: " + lnk_info['volumedroid_birth'] + "\n"
        output += "filedroid: " + lnk_info['filedroid'] + "\n"
        output += "filedroid_birth: " + lnk_info['filedroid_birth'] + "\n"
    
    return output


def usage():
    print "Usage: ./pylnker.py .LNK_FILE"
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        usage()

    filename = sys.argv[1]
    flags = None
    struct_end = 76
    with open(filename, 'rb') as f:
        lnk_info, flags = parse_shell_link_header(filename, f, flags)
        
        # need to make sections optional in format_output
        if search(lnk_info['link flags'], ['HasLinkTargetIDList']) == True:
            print "HasLinkTargetIDList = True"
            lnk_info, struct_end = parse_linktarget_idlist(lnk_info, f, struct_end)
        
        if search(lnk_info['link flags'], ['HasLinkInfo']) == True:
            print "HasLinkInfo = True"
            lnk_info, struct_end = parse_linkinfo(lnk_info, f, struct_end)
            
        if search(lnk_info['link flags'], ['HasName', 'HasRelativePath', 'HasWorkingDir', 'HasArguments', 'HasIconLocation']) == True:
            print "String Data = True"
            lnk_info, struct_end = parse_string_data(lnk_info, f, flags, struct_end)
        
        parse_extra_data(lnk_info, f)

        print format_output(lnk_info)

if __name__ == "__main__":
    main()
