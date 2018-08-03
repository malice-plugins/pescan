from __future__ import absolute_import

import hashlib

import chardet
import os
import time
from cStringIO import StringIO
from _io import BytesIO
import binascii
from pyasn1.codec.der import encoder as der_encoder
import json
import pprint
import logging
import traceback

from assemblyline.common.charset import safe_str, translate_str
from textwrap import dedent
from assemblyline.common.hexdump import hexdump
from assemblyline.al.common.result import Result, ResultSection
from assemblyline.al.common.result import SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT, TAG_USAGE
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.service.base import ServiceBase
from .lcid import LCID as G_LCID



# Some legacy stubs
def res_txt_tag_charset(text, tag, encoding, confidence, style=None, link=None, alt_text=None):
    return res_txt_tag(text + ' - encoding:' + str(encoding) + ' confidence: ' + str(confidence),
                       tag, style, link, alt_text)


# noinspection PyUnusedLocal
def res_txt_tag(value, tag, style=None, link=None, alt_text=None):
    return value


def make_tag(res, ttype, tag, weight, usage):
    try:
        t = str(tag)
    except:
        return
    if 1 < len(t) < 1001:
        res.add_tag(TAG_TYPE[ttype], t, TAG_WEIGHT[weight], usage=usage)
    return


PEFILE_SLACK_LENGTH_TO_DISPLAY = 256


class PEFile(ServiceBase):
    """ This services dumps the PE header and attempts to find
    some anomalies which could indicate that they are malware related.

    PEiD signature style searching should be done using the yara service"""
    SERVICE_ACCEPTS = 'executable/windows'
    SERVICE_CATEGORY = "Static Analysis"
    SERVICE_DESCRIPTION = "This service extracts imports, exports, section names, ... " \
                          "from windows PE files using the python library pefile."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.2
    SERVICE_RAM_MB = 256

    # Heuristic info
    AL_PEFile_001 = Heuristic("AL_PEFile_001", "Invalid Signature", "executable/windows",
                              dedent("""\
                                         Signature data found in PE but doesn't match the content.
                                         This is either due to malicious copying of signature data or
                                         an error in transmission.
                                         """))
    AL_PEFile_002 = Heuristic("AL_PEFile_002", "Legitimately Signed EXE", "executable/windows",
                              dedent("""\
                                         This PE appears to have a legitimate signature.
                                         """))
    AL_PEFile_003 = Heuristic("AL_PEFile_003", "Self Signed", "executable/windows",
                              dedent("""\
                                         This PE appears is self-signed
                                         """))

    # noinspection PyGlobalUndefined,PyUnresolvedReferences
    def import_service_deps(self):
        global pefile
        import pefile

        try:
            global signed_pe, signify
            from signify import signed_pe
            import signify
            self.use_signify = True
        except ImportError:
            self.log.warning("signify package not installed (unable to import). Reinstall the PEFile service with "
                             "/opt/al/assemblyline/al/install/reinstall_service.py PEFile")

    def __init__(self, cfg=None):
        super(PEFile, self).__init__(cfg)
        # Service Initialization
        self.log.debug("LCID DB loaded (%s entries). Running information parsing..." % (len(G_LCID),))
        self.filesize_from_peheader = -1
        self.print_slack = False
        self.pe_file = None
        self._sect_list = None
        self.entropy_warning = False
        self.file_res = None
        self.unexpected_sname = []
        self.import_hash = None
        self.filename = None
        self.patch_section = None
        self.request = None
        self.path = None
        self.use_signify = False

    def get_imphash(self):
        return self.pe_file.get_imphash()

    # noinspection PyPep8Naming
    def get_pe_info(self, lcid):
        """Dumps the PE header as Results in the FileResult."""

        # PE Header
        pe_header_res = ResultSection(SCORE['NULL'], "PE: HEADER")

        # PE Header: Header Info
        pe_header_info_res = ResultSection(SCORE.NULL, "[HEADER INFO]", parent=pe_header_res)
        pe_header_info_res.add_line("Entry point address: 0x%08X" % self.pe_file.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe_header_info_res.add_line("Linker Version: %02d.%02d" % (self.pe_file.OPTIONAL_HEADER.MajorLinkerVersion,
                                                                   self.pe_file.OPTIONAL_HEADER.MinorLinkerVersion))
        pe_header_info_res.add_line("OS Version: %02d.%02d" %
                                    (self.pe_file.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                                     self.pe_file.OPTIONAL_HEADER.MinorOperatingSystemVersion))
        pe_header_info_res.add_line(["Time Date Stamp: %s (" % time.ctime(self.pe_file.FILE_HEADER.TimeDateStamp),
                                     res_txt_tag(str(self.pe_file.FILE_HEADER.TimeDateStamp),
                                                 TAG_TYPE['PE_LINK_TIME_STAMP']),
                                     ")"])
        try:
            pe_header_info_res.add_line("Machine Type: %s (%s)" % (
                hex(self.pe_file.FILE_HEADER.Machine), pefile.MACHINE_TYPE[self.pe_file.FILE_HEADER.Machine]))
        except KeyError:
            pass

        # PE Header: Rich Header
        # noinspection PyBroadException
        try:

            if self.pe_file.RICH_HEADER is not None:
                pe_rich_header_info = ResultSection(SCORE.NULL, "[RICH HEADER INFO]", parent=pe_header_res)
                values_list = self.pe_file.RICH_HEADER.values
                pe_rich_header_info.add_line("VC++ tools used:")
                for i in range(0, len(values_list) / 2):
                    line = "Tool Id: %3d Version: %6d Times used: %3d" % (
                        values_list[2 * i] >> 16, values_list[2 * i] & 0xFFFF, values_list[2 * i + 1])
                    pe_rich_header_info.add_line(line)
        except:
            self.log.exception("Unable to parse PE Rich Header")

        # PE Header: Data Directories
        pe_dd_res = ResultSection(SCORE.NULL, "[DATA DIRECTORY]", parent=pe_header_res)
        for data_directory in self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY:
            if data_directory.Size or data_directory.VirtualAddress:
                pe_dd_res.add_line("%s - va: 0x%08X - size: 0x%08X"
                                   % (data_directory.name[len("IMAGE_DIRECTORY_ENTRY_"):],
                                      data_directory.VirtualAddress, data_directory.Size))

        # PE Header: Sections
        pe_sec_res = ResultSection(SCORE.NULL, "[SECTIONS]", parent=pe_header_res)

        self._init_section_list()

        try:
            for (sname, section, sec_md5, sec_entropy) in self._sect_list:
                txt = [sname, " - Virtual: 0x%08X (0x%08X bytes)"
                              " - Physical: 0x%08X (0x%08X bytes) - " %
                       (section.VirtualAddress, section.Misc_VirtualSize,
                        section.PointerToRawData, section.SizeOfRawData), "hash:",
                       res_txt_tag(sec_md5, TAG_TYPE['PE_SECTION_HASH']),
                       " - entropy:%f (min:0.0, Max=8.0)" % sec_entropy]
                # add a search tag for the Section Hash
                make_tag(self.file_res, 'PE_SECTION_HASH', sec_md5, 'HIGH', usage='CORRELATION')
                pe_sec_res.add_line(txt)

        except AttributeError:
            pass

        self.file_res.add_section(pe_header_res)

        # debug
        try:
            if self.pe_file.DebugTimeDateStamp:
                pe_debug_res = ResultSection(SCORE['NULL'], "PE: DEBUG")
                self.file_res.add_section(pe_debug_res)

                pe_debug_res.add_line("Time Date Stamp: %s" % time.ctime(self.pe_file.DebugTimeDateStamp))

                # When it is a unicode, we know we are coming from RSDS which is UTF-8
                # otherwise, we come from NB10 and we need to guess the charset.
                if type(self.pe_file.pdb_filename) != unicode:
                    char_enc_guessed = translate_str(self.pe_file.pdb_filename)
                    pdb_filename = char_enc_guessed['converted']
                else:
                    char_enc_guessed = {'confidence': 1.0, 'encoding': 'utf-8'}
                    pdb_filename = self.pe_file.pdb_filename

                pe_debug_res.add_line(["PDB: '",
                                       res_txt_tag_charset(pdb_filename,
                                                           TAG_TYPE['PE_PDB_FILENAME'],
                                                           char_enc_guessed['encoding'],
                                                           char_enc_guessed['confidence']),
                                       "'"])

                # self.log.debug(u"\tPDB: %s" % pdb_filename)
        except AttributeError:
            pass

        # imports
        try:
            if hasattr(self.pe_file, 'DIRECTORY_ENTRY_IMPORT') and len(self.pe_file.DIRECTORY_ENTRY_IMPORT) > 0:
                pe_import_res = ResultSection(SCORE['NULL'], "PE: IMPORTS")
                self.file_res.add_section(pe_import_res)

                for entry in self.pe_file.DIRECTORY_ENTRY_IMPORT:
                    pe_import_dll_res = ResultSection(SCORE.NULL, "[%s]" % entry.dll, parent=pe_import_res)
                    first_element = True
                    line = StringIO()
                    for imp in entry.imports:
                        if first_element:
                            first_element = False
                        else:
                            line.write(", ")

                        if imp.name is None:
                            line.write(str(imp.ordinal))
                        else:
                            line.write(imp.name)

                    pe_import_dll_res.add_line(line.getvalue())

            else:
                pe_import_res = ResultSection(SCORE['NULL'], "PE: NO IMPORTS DETECTED ")
                self.file_res.add_section(pe_import_res)

        except AttributeError:
            pass

        # exports
        try:
            if self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp is not None:
                pe_export_res = ResultSection(SCORE['NULL'], "PE: EXPORTS")
                self.file_res.add_section(pe_export_res)

                # noinspection PyBroadException
                try:
                    pe_export_res.add_line(["Module Name: ",
                                            res_txt_tag(safe_str(self.pe_file.ModuleName),
                                                        TAG_TYPE['PE_EXPORT_MODULE_NAME'])])
                except:
                    pass

                if self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp == 0:
                    pe_export_res.add_line("Time Date Stamp: 0")
                else:
                    pe_export_res.add_line("Time Date Stamp: %s"
                                           % time.ctime(self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp))

                first_element = True
                txt = []
                for exp in self.pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                    if first_element:
                        first_element = False
                    else:
                        txt.append(", ")

                    txt.append(str(exp.ordinal))
                    if exp.name is not None:
                        txt.append(": ")
                        txt.append(res_txt_tag(exp.name, TAG_TYPE['PE_EXPORT_FCT_NAME']))

                pe_export_res.add_line(txt)
        except AttributeError:
            pass

        # resources
        try:
            if len(self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries) > 0:
                pe_resource_res = ResultSection(SCORE['NULL'], "PE: RESOURCES")
                self.file_res.add_section(pe_resource_res)

                for res_entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                    if res_entry.name is None:
                        # noinspection PyBroadException
                        try:
                            entry_name = pefile.RESOURCE_TYPE[res_entry.id]
                        except:
                            # pylint: disable-msg=W0702
                            # unfortunately this code was done before we started to really care about which
                            # exception to catch so, I actually don't really know at this point, would need to try
                            # out :-\
                            entry_name = "UNKNOWN"
                    else:
                        entry_name = res_entry.name

                    for name_id in res_entry.directory.entries:
                        if name_id.name is None:
                            name_id.name = hex(name_id.id)

                        for language in name_id.directory.entries:
                            try:
                                language_desc = lcid[language.id]
                            except KeyError:
                                language_desc = 'Unknown language'

                            line = []
                            if res_entry.name is None:
                                line.append(entry_name)
                            else:
                                line.append(res_txt_tag(str(entry_name), TAG_TYPE['PE_RESOURCE_NAME']))

                            line.append(" " + str(name_id.name) + " ")
                            line.append("0x")
                            # this will add a link to search in AL for the value
                            line.append(res_txt_tag("%04X" % language.id, TAG_TYPE['PE_RESOURCE_LANGUAGE']))
                            line.append(" (%s)" % language_desc)

                            make_tag(self.file_res, 'PE_RESOURCE_LANGUAGE', language.id,
                                     weight='LOW', usage='IDENTIFICATION')

                            # get the size of the resource
                            res_size = language.data.struct.Size
                            line.append(" Size: 0x%x" % res_size)

                            pe_resource_res.add_line(line)

        except AttributeError:
            pass

        # Resources-VersionInfo
        try:
            if len(self.pe_file.FileInfo) > 2:
                pass

            for file_info in self.pe_file.FileInfo:
                if file_info.name == "StringFileInfo":
                    if len(file_info.StringTable) > 0:
                        pe_resource_verinfo_res = ResultSection(SCORE['NULL'], "PE: RESOURCES-VersionInfo")
                        self.file_res.add_section(pe_resource_verinfo_res)

                        try:
                            if "LangID" in file_info.StringTable[0].entries:
                                lang_id = file_info.StringTable[0].get("LangID")
                                if not int(lang_id, 16) >> 16 == 0:
                                    txt = ('LangId: ' + lang_id + " (" + lcid[
                                        int(lang_id, 16) >> 16] + ")")
                                    pe_resource_verinfo_res.add_line(txt)
                                else:
                                    txt = ('LangId: ' + lang_id + " (NEUTRAL)")
                                    pe_resource_verinfo_res.add_line(txt)
                        except (ValueError, KeyError):
                            txt = ('LangId: %s is invalid' % lang_id)
                            pe_resource_verinfo_res.add_line(txt)

                        for entry in file_info.StringTable[0].entries.items():
                            txt = ['%s: ' % entry[0]]

                            if entry[0] == 'OriginalFilename':
                                txt.append(res_txt_tag(entry[1], TAG_TYPE['PE_VERSION_INFO_ORIGINAL_FILENAME']))
                            elif entry[0] == 'FileDescription':
                                txt.append(res_txt_tag(entry[1], TAG_TYPE['PE_VERSION_INFO_FILE_DESCRIPTION']))
                            else:
                                txt.append(entry[1])

                            pe_resource_verinfo_res.add_line(txt)

        except AttributeError:
            pass

        # Resources Strings
        try:
            BYTE = 1
            WORD = 2
            DWORD = 4

            DS_SETFONT = 0x40

            DIALOG_LEAD = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
            DIALOG_ITEM_LEAD = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD

            DIALOGEX_LEAD = WORD + WORD + DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
            DIALOGEX_TRAIL = WORD + WORD + BYTE + BYTE
            DIALOGEX_ITEM_LEAD = DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + DWORD
            DIALOGEX_ITEM_TRAIL = WORD

            ITEM_TYPES = {0x80: "BUTTON", 0x81: "EDIT", 0x82: "STATIC", 0x83: "LIST BOX", 0x84: "SCROLL BAR",
                          0x85: "COMBO BOX"}

            if hasattr(self.pe_file, 'DIRECTORY_ENTRY_RESOURCE'):
                for dir_type in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                    if dir_type.name is None:
                        if dir_type.id in pefile.RESOURCE_TYPE:
                            dir_type.name = pefile.RESOURCE_TYPE[dir_type.id]
                    for nameID in dir_type.directory.entries:
                        if nameID.name is None:
                            nameID.name = hex(nameID.id)
                        for language in nameID.directory.entries:
                            strings = []
                            if str(dir_type.name) == "RT_DIALOG":
                                data_rva = language.data.struct.OffsetToData
                                size = language.data.struct.Size
                                data = self.pe_file.get_memory_mapped_image()[data_rva:data_rva + size]

                                offset = 0
                                if self.pe_file.get_word_at_rva(data_rva + offset) == 0x1 \
                                        and self.pe_file.get_word_at_rva(data_rva + offset + WORD) == 0xFFFF:
                                    # Use Extended Dialog Parsing

                                    # Remove leading bytes
                                    offset += DIALOGEX_LEAD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += WORD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += WORD

                                    # Get window title
                                    window_title = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                    if len(window_title) != 0:
                                        strings.append(("DIALOG_TITLE", window_title))
                                    offset += len(window_title) * 2 + WORD

                                    # Remove trailing bytes
                                    offset += DIALOGEX_TRAIL
                                    offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                    # alignment adjustment
                                    if (offset % 4) != 0:
                                        offset += WORD

                                    while True:

                                        if offset >= size:
                                            break

                                        offset += DIALOGEX_ITEM_LEAD

                                        # Get item type
                                        if self.pe_file.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                            offset += WORD
                                            item_type = ITEM_TYPES[self.pe_file.get_word_at_rva(data_rva + offset)]
                                            offset += WORD
                                        else:
                                            item_type = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                            offset += len(item_type) * 2 + WORD

                                        # Get item text
                                        item_text = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                        if len(item_text) != 0:
                                            strings.append((item_type, item_text))
                                        offset += len(item_text) * 2 + WORD

                                        extra_bytes = self.pe_file.get_word_at_rva(data_rva + offset)
                                        offset += extra_bytes + DIALOGEX_ITEM_TRAIL

                                        # Alignment adjustment
                                        if (offset % 4) != 0:
                                            offset += WORD

                                else:
                                    # TODO: Use Non extended Dialog Parsing
                                    # Remove leading bytes
                                    style = self.pe_file.get_word_at_rva(data_rva + offset)

                                    offset += DIALOG_LEAD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                    # Get window title
                                    window_title = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                    if len(window_title) != 0:
                                        strings.append(("DIALOG_TITLE", window_title))
                                    offset += len(window_title) * 2 + WORD

                                    if (style & DS_SETFONT) != 0:
                                        offset += WORD
                                        offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                    # Alignment adjustment
                                    if (offset % 4) != 0:
                                        offset += WORD

                                    while True:

                                        if offset >= size:
                                            break

                                        offset += DIALOG_ITEM_LEAD

                                        # Get item type
                                        if self.pe_file.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                            offset += WORD
                                            item_type = ITEM_TYPES[self.pe_file.get_word_at_rva(data_rva + offset)]
                                            offset += WORD
                                        else:
                                            item_type = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                            offset += len(item_type) * 2 + WORD

                                        # Get item text
                                        if self.pe_file.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                            offset += DWORD
                                        else:
                                            item_text = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                            if len(item_text) != 0:
                                                strings.append((item_type, item_text))
                                            offset += len(item_text) * 2 + WORD

                                        extra_bytes = self.pe_file.get_word_at_rva(data_rva + offset)
                                        offset += extra_bytes + WORD

                                        # Alignment adjustment
                                        if (offset % 4) != 0:
                                            offset += WORD

                            elif str(dir_type.name) == "RT_STRING":
                                data_rva = language.data.struct.OffsetToData
                                size = language.data.struct.Size
                                data = self.pe_file.get_memory_mapped_image()[data_rva:data_rva + size]
                                offset = 0
                                while True:
                                    if offset >= size:
                                        break

                                    ustr_length = self.pe_file.get_word_from_data(data[offset:offset + 2], 0)
                                    offset += 2

                                    if ustr_length == 0:
                                        continue

                                    ustr = self.pe_file.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
                                    offset += ustr_length * 2
                                    strings.append((None, ustr))

                            if len(strings) > 0:
                                success = False
                                try:
                                    comment = "%s (id:%s - lang_id:0x%04X [%s])" % (
                                        str(dir_type.name), str(nameID.name), language.id, lcid[language.id])
                                except KeyError:
                                    comment = "%s (id:%s - lang_id:0x%04X [Unknown language])" % (
                                        str(dir_type.name), str(nameID.name), language.id)
                                res = ResultSection(SCORE['NULL'], "PE: STRINGS - %s" % comment)
                                for idx in xrange(len(strings)):
                                    # noinspection PyBroadException
                                    try:
                                        tag_value = strings[idx][1]

                                        # The following line crash chardet if a
                                        # UPX packed file as packed the resources...
                                        chardet.detect(tag_value)  # TODO: Find a better way to do this

                                        tag_value = tag_value.replace('\r', ' ').replace('\n', ' ')
                                        if strings[idx][0] is not None:
                                            res.add_line(
                                                [strings[idx][0], ": ",
                                                 res_txt_tag(tag_value, TAG_TYPE['FILE_STRING'])])
                                        else:
                                            res.add_line(res_txt_tag(tag_value, TAG_TYPE['FILE_STRING']))

                                        make_tag(self.file_res, 'FILE_STRING', tag_value, weight='NULL',
                                                 usage='IDENTIFICATION')

                                        success = True
                                    except:
                                        pass
                                if success:
                                    self.file_res.add_section(res)
                else:
                    pass

        except AttributeError, e:
            self.log.debug("\t Error parsing output: " + repr(e))

        except Exception, e:
            print e

        # print slack space if it exists
        if (self.print_slack and self.filesize_from_peheader > 0 and (
                len(self.pe_file.__data__) > self.filesize_from_peheader)):
            length_to_display = PEFILE_SLACK_LENGTH_TO_DISPLAY
            if length_to_display > 0:
                length_display_str = ""
                slack_size = len(self.pe_file.__data__) - self.filesize_from_peheader
                if slack_size > length_to_display:
                    length_display_str = "- displaying first %d bytes" % length_to_display
                pe_slack_space_res = ResultSection(SCORE['NULL'],
                                                   "PE: SLACK SPACE (The file contents after the PE file size ends) "
                                                   "[%d bytes] %s" % (
                                                       len(self.pe_file.__data__) - self.filesize_from_peheader,
                                                       length_display_str),
                                                   body_format=TEXT_FORMAT['MEMORY_DUMP'])
                pe_slack_space_res.add_line(hexdump(
                    self.pe_file.__data__[self.filesize_from_peheader:self.filesize_from_peheader + length_to_display]))
                self.file_res.add_section(pe_slack_space_res)

    def _init_section_list(self):
        # Lazy init
        if self._sect_list is None:
            self._sect_list = []
            try:
                for section in self.pe_file.sections:
                    zero_idx = section.Name.find(chr(0x0))
                    if not zero_idx == -1:
                        sname = section.Name[:zero_idx]
                    else:
                        sname = safe_str(section.Name)
                    entropy = section.get_entropy()
                    self._sect_list.append((sname, section, section.get_hash_md5(), entropy))
            except AttributeError:
                pass

    def get_export_module_name(self):

        try:
            section = self.pe_file.get_section_by_rva(self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.Name)
            offset = section.get_offset_from_rva(self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.Name)
            self.pe_file.ModuleName = self.pe_file.__data__[offset:offset + self.pe_file.__data__[offset:].find(chr(0))]
        except AttributeError:
            pass

    def get_import_hash(self):
        try:
            if (self.import_hash is None and
                    len(self.pe_file.DIRECTORY_ENTRY_IMPORT) > 0):
                sorted_import_list = []
                for entry in self.pe_file.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name is None:
                            sorted_import_list.append(str(imp.ordinal))
                        else:
                            sorted_import_list.append(imp.name)

                sorted_import_list.sort()
                self.import_hash = hashlib.sha1(" ".join(sorted_import_list)).hexdigest()
        except AttributeError:
            pass

        return self.import_hash

    def auto_generate_tags(self, file_res):

        try:
            make_tag(file_res, 'FILE_NAME', self.pe_file.ModuleName, weight='MED', usage="CORRELATION")

            make_tag(file_res, 'PE_EXPORT_MODULE_NAME', self.pe_file.ModuleName, weight='HIGH', usage="CORRELATION")
        except:
            pass

        make_tag(file_res, 'PE_LINK_TIME_STAMP', self.pe_file.FILE_HEADER.TimeDateStamp, weight='HIGH',
                 usage="CORRELATION")
        try:
            # When it is a unicode, we know we are coming from RSDS which is UTF-8
            # otherwise, we come from NB10 and we need to guess the charset.
            if type(self.pe_file.pdb_filename) != unicode:
                char_enc_guessed = translate_str(self.pe_file.pdb_filename)
                pdb_filename = char_enc_guessed['converted']
            else:
                pdb_filename = self.pe_file.pdb_filename

            make_tag(file_res, 'PE_PDB_FILENAME', pdb_filename, weight='HIGH', usage="CORRELATION")
        except AttributeError:
            pass

        try:
            if len(self.pe_file.OriginalFilename) > 0:
                make_tag(file_res, 'PE_VERSION_INFO_ORIGINAL_FILENAME', self.pe_file.OriginalFilename, weight='HIGH',
                         usage="CORRELATION")
        except AttributeError:
            pass

        try:
            if len(self.pe_file.FileDescription) > 0:
                make_tag(file_res, 'PE_VERSION_INFO_FILE_DESCRIPTION', self.pe_file.FileDescription, weight='HIGH',
                         usage="CORRELATION")
        except AttributeError:
            pass

        # We have always been sorting them and storing the sorted hash, but we have added
        # unsorted MD5-hash (which is provided by PEFILE) so this has been renamed
        if self.get_import_hash() is not None:
            make_tag(file_res, 'PE_IMPORT_SORTED_SHA1', self.get_import_hash(), weight='HIGH', usage="CORRELATION")

        imphash = self.get_imphash()
        if imphash != '':
            make_tag(file_res, 'PE_IMPORT_MD5', imphash, weight='HIGH', usage="CORRELATION")

        try:
            if self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp:
                for exp in self.pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name is not None:
                        make_tag(file_res, 'PE_EXPORT_FCT_NAME', exp.name, weight='HIGH', usage="CORRELATION")
        except AttributeError:
            pass

        try:
            if len(self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries) > 0:
                for res_entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                    if res_entry.name is not None:
                        make_tag(file_res, 'PE_RESOURCE_NAME', res_entry.name, weight='HIGH', usage="CORRELATION")

                    for name_id in res_entry.directory.entries:
                        if name_id.name is not None:
                            make_tag(file_res, 'PE_RESOURCE_NAME', name_id.name, weight='HIGH', usage="CORRELATION")
        except AttributeError:
            pass

    def execute(self, request):
        request.result = Result()
        self.file_res = request.result
        self.path = request.download()
        filename = os.path.basename(self.path)
        self.request = request

        self.pe_file = None
        self._sect_list = None
        self.entropy_warning = False
        self.unexpected_sname = []
        self.import_hash = None
        self.filename = filename
        self.print_slack = True
        self.patch_section = None
        self.filesize_from_peheader = -1

        with open(self.path, 'r') as f:
            file_content = f.read()

        try:
            self.pe_file = pefile.PE(data=file_content)
        except pefile.PEFormatError, e:
            if e.value != "DOS Header magic not found.":
                res = ResultSection(SCORE['HIGH'],
                                    ["WARNING: this file looks like a PE but failed loading inside PE file. [", e.value,
                                     "]"])
                self.file_res.add_section(res)
            self.log.debug(e)

        if self.pe_file is not None:

            # This is just to get pylint to stop complaining about those member variables not being available.
            if False:
                self.pe_file.DebugTimeDateStamp = None
                self.pe_file.DIRECTORY_ENTRY_EXPORT = None
                self.pe_file.DIRECTORY_ENTRY_IMPORT = None
                self.pe_file.DIRECTORY_ENTRY_RESOURCE = None
                self.pe_file.pdb_filename = None
                self.pe_file.OPTIONAL_HEADER.AddressOfEntryPoint = None
                self.pe_file.FILE_HEADER.Machine = None
                self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY = None
                self.pe_file.OPTIONAL_HEADER.MajorLinkerVersion = None
                self.pe_file.OPTIONAL_HEADER.MinorLinkerVersion = None
                self.pe_file.OPTIONAL_HEADER.MajorOperatingSystemVersion = None
                self.pe_file.OPTIONAL_HEADER.MinorOperatingSystemVersion = None
                self.pe_file.FILE_HEADER.TimeDateStamp = None
                self.pe_file.DIRECTORY_ENTRY_DEBUG = None
                self.pe_file.OPTIONAL_HEADER.CheckSum = None
                self.pe_file.OPTIONAL_HEADER.ImageBase = None
                self.pe_file.OPTIONAL_HEADER.MajorImageVersion = None
                self.pe_file.OPTIONAL_HEADER.MinorImageVersion = None
                self.pe_file.OPTIONAL_HEADER.Subsystem = None
                self.pe_file.OriginalFilename = None
                self.pe_file.FileDescription = None
                self.pe_file.ModuleName = None

            self.get_export_module_name()

            # Auto generate signatures...
            self.auto_generate_tags(self.file_res)

            # Here is general PE info
            self.get_pe_info(G_LCID)

            file_io = BytesIO(file_content)

            extracted_data = None
            try:
                extracted_data = PEFile.get_signify(file_io, self.file_res, self.log)
            except Exception as e:
                res = ResultSection(SCORE.NULL, "Error trying to check for PE signatures")
                res.add_line("Traceback:")
                res.add_lines(traceback.format_exc().splitlines())

                self.file_res.add_section(res)

    @staticmethod
    def get_signify(file_handle, res, log = None):

        if log == None:
            log = logging.getLogger("get_signify")
        else:
            log = log.getChild("get_signify")

        # first, let's try parsing the file
        try:
            s_data = signed_pe.SignedPEFile(file_handle)
        except Exception as e:
            log.error("Error parsing. May not be a valid PE? Traceback: %s" % traceback.format_exc())

        # Now try checking for verification
        try:
            s_data.verify()

            # signature is verified
            res.add_section(ResultSection(SCORE.OK, "This file is signed"))
            res.report_heuristic(PEFile.AL_PEFile_002)

        except signify.exceptions.SignedPEParseError as e:
            if e.message == "The PE file does not contain a certificate table.":
                res.add_section(ResultSection(SCORE.NULL, "No file signature data found"))

            else:
                res.add_section(ResultSection(SCORE.NULL, "Unknown exception. Traceback: %s" % traceback.format_exc()))

        except signify.exceptions.AuthenticodeVerificationError as e:
            if e.message == "The expected hash does not match the digest in SpcInfo":
                # This sig has been copied from another program
                res.add_section(ResultSection(SCORE.HIGH, "The signature does not match the program data"))
                res.report_heuristic(PEFile.AL_PEFile_001)
            else:
                res.add_section(ResultSection(SCORE.NULL, "Unknown authenticode exception. Traceback: %s" % traceback.format_exc()))

        except signify.exceptions.VerificationError as e:
            if e.message.startswith("Chain verification from"):
                # probably self signed
                res.add_section(ResultSection(SCORE.MED, "File is self-signed"))
                res.report_heuristic(PEFile.AL_PEFile_003)
            else:
                res.add_section(
                    ResultSection(SCORE.NULL, "Unknown exception. Traceback: %s" % traceback.format_exc()))


        # Now try to get certificate and signature data
        sig_datas = []
        try:
            sig_datas.extend([x for x in s_data.signed_datas])
        except:
            pass

        if len(sig_datas) > 0:
            # Now extract certificate data from the sig
            for s in sig_datas:
                # Extract signer info. This is probably the most useful?
                res.add_tag(TAG_TYPE.CERT_SERIAL_NO, str(s.signer_info.serial_number))
                res.add_tag(TAG_TYPE.CERT_ISSUER, s.signer_info.issuer_dn)

                # Get cert used for signing, then add valid from/to info
                for cert in [x for x in s.certificates if x.serial_number == s.signer_info.serial_number]:
                    res.add_tag(TAG_TYPE.CERT_SUBJECT, cert.subject_dn)
                    res.add_tag(TAG_TYPE.CERT_VALID_FROM, cert.valid_from.isoformat())
                    res.add_tag(TAG_TYPE.CERT_VALID_TO, cert.valid_to.isoformat())

                for cert in s.certificates:
                    cert_res = ResultSection(SCORE.NULL, "Certificate Information")
                    # x509 CERTIFICATES
                    # ('CERT_VERSION', 230),
                    # ('CERT_SERIAL_NO', 231),
                    # ('CERT_SIGNATURE_ALGO', 232),
                    # ('CERT_ISSUER', 233),
                    # ('CERT_VALID_FROM', 234),
                    # ('CERT_VALID_TO', 235),
                    # ('CERT_SUBJECT', 236),
                    # ('CERT_KEY_USAGE', 237),
                    # ('CERT_EXTENDED_KEY_USAGE', 238),
                    # ('CERT_SUBJECT_ALT_NAME', 239),
                    # ('CERT_THUMBPRINT', 240),

                    # probably not worth doing tags for all this info?
                    cert_res.add_lines(["CERT_VERSION: %d" % cert.version,
                                        "CERT_SERIAL_NO: %d" % cert.serial_number,
                                        "CERT_ISSUER: %s" % cert.issuer_dn,
                                        "CERT_SUBJECT: %s" % cert.subject_dn,
                                        "CERT_VALID_FROM: %s" % cert.valid_from.isoformat(),
                                        "CERT_VALID_TO: %s" % cert.valid_to.isoformat()])
                    # cert_res.add_tag(TAG_TYPE.CERT_VERSION, str(cert.version))
                    # cert_res.add_tag(TAG_TYPE.CERT_SERIAL_NO, str(cert.serial_number))
                    # cert_res.add_tag(TAG_TYPE.CERT_ISSUER, cert.issuer_dn)
                    # cert_res.add_tag(TAG_TYPE.CERT_VALID_FROM, cert.valid_from.isoformat())
                    # cert_res.add_tag(TAG_TYPE.CERT_VALID_TO, cert.valid_to.isoformat())
                    # cert_res.add_tag(TAG_TYPE.CERT_SUBJECT, cert.subject_dn)

                    res.add_section(cert_res)
        # pprint.pprint(file_res)


if __name__ == "__main__":

    import sys

    from signify import signed_pe
    import signify

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)s %(levelname)s %(message)s')

    file_io = BytesIO(open(sys.argv[1],"rb").read())
    res = Result()
    PEFile.get_signify(file_io, res)
    # try:
    #     s_data = signed_pe.SignedPEFile(file_io)
    # except Exception as e:
    #     print "Exception parsing data"
    #     traceback.print_exc()
    #     msg = e.message
    #
    # try:
    #     s_data.verify()
    # except Exception as e:
    #     traceback.print_exc()
    #     print "====="
    #     print e.message
    #
    # pprint.pprint(s_data)
