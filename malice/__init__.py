# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = 'Malice PExecutable Plugin - pefile helper util'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/08/18'

import datetime
import json
import logging
import re
import tempfile
import time
from io import BytesIO
from os import path
from collections import Iterable
import chardet

import pefile
import peutils
from future.builtins import open
from pehash.pehasher import calculate_pehash
from sig import get_signify
from utils import get_entropy, get_md5, get_sha256, get_type, sha256_checksum
from utils.charset import safe_str, translate_str

from .lcid import LCID

# from verifysigs.asn1utils import dn
# from verifysigs.sigs_helper import get_auth_data

log = logging.getLogger(__name__)


class MalPEFile(object):

    def __init__(self, file_path, peid_db_path, should_dump=False, dump_path=None):
        self.file = file_path
        self.sha256 = sha256_checksum(self.file)
        self.data = open(file_path, 'rb').read()
        self.peid_db = peid_db_path
        self.dump = None
        self.pe = None
        self.results = {}
        self.result_compile_time = None
        self.result_sections = None
        if not path.exists(self.file):
            raise Exception("file does not exist: {}".format(self.file))
        if should_dump:
            if path.isdir(dump_path):
                self.dump = dump_path
            else:
                log.error("folder does not exist: {}".format(dump_path))
                self.dump = None

    def info(self):
        info = {}
        if hasattr(self.pe, 'OriginalFilename'):
            info['original_filename'] = self.pe.OriginalFilename
        if hasattr(self.pe, 'FileDescription'):
            info['file_description'] = self.pe.FileDescription
        if hasattr(self.pe, 'OPTIONAL_HEADER'):
            info['image_base'] = self.pe.OPTIONAL_HEADER.ImageBase
            info['size_of_image'] = self.pe.OPTIONAL_HEADER.SizeOfImage
            info['linker_version'] = "{:02d}.{:02d}".format(self.pe.OPTIONAL_HEADER.MajorLinkerVersion,
                                                            self.pe.OPTIONAL_HEADER.MinorLinkerVersion)
            info['os_version'] = "{:02d}.{:02d}".format(self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                                                        self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
            data = []
            for data_directory in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if data_directory.Size or data_directory.VirtualAddress:
                    data.append({
                        'name': data_directory.name[len("IMAGE_DIRECTORY_ENTRY_"):],
                        'virtual_address': hex(data_directory.VirtualAddress),
                        'size': data_directory.Size
                    })
            self.results['data_directories'] = data
        if hasattr(self.pe, 'FILE_HEADER'):
            info['number_of_sections'] = self.pe.FILE_HEADER.NumberOfSections
            info['machine_type'] = "{} ({})".format(
                hex(self.pe.FILE_HEADER.Machine), pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine])
        if hasattr(self.pe, 'RICH_HEADER') and self.pe.RICH_HEADER is not None:
            rich_header_info = []
            values_list = self.pe.RICH_HEADER.values
            for i in range(0, len(values_list) / 2):
                line = {
                    'tool_id': values_list[2 * i] >> 16,
                    'version': values_list[2 * i] & 0xFFFF,
                    'times used': values_list[2 * i + 1]
                }
                rich_header_info.append(line)
            self.results['rich_header_info'] = rich_header_info
        self.results['info'] = info

    def debug(self):
        if hasattr(self.pe, 'DebugTimeDateStamp'):
            debug = {}
            debug['time_date_stamp'] = "%s" % time.ctime(self.pe.DebugTimeDateStamp)

            # When it is a unicode, we know we are coming from RSDS which is UTF-8
            # otherwise, we come from NB10 and we need to guess the charset.
            if not isinstance(self.pe.pdb_filename, unicode):
                char_enc_guessed = translate_str(self.pe.pdb_filename)
                pdb_filename = char_enc_guessed['converted']
            else:
                char_enc_guessed = {'confidence': 1.0, 'encoding': 'utf-8'}
                pdb_filename = self.pe.pdb_filename

            debug['time_date_stamp'] = pdb_filename
            self.results['debug'] = debug

    def imports(self):
        imports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT') and len(self.pe.DIRECTORY_ENTRY_IMPORT) > 0:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    if isinstance(entry.dll, bytes):
                        dll = entry.dll.decode()
                    else:
                        dll = entry.dll
                    log.info("DLL: {0}".format(dll))
                    dlls = {dll: []}
                    for symbol in entry.imports:
                        if isinstance(symbol.name, bytes):
                            name = symbol.name.decode()
                        else:
                            name = symbol.name
                        dlls[dll].append(dict(address=hex(symbol.address), name=name))
                    imports.append(dlls)
                    # self.log('item', "{0}: {1}".format(hex(symbol.address), name))
                except Exception:
                    continue
        self.results['imports'] = imports

    def exports(self):
        exports = []
        if hasattr(self.pe,
                   'DIRECTORY_ENTRY_EXPORT') and self.pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp is not None:
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append(
                    dict(
                        address=hex(self.pe.OPTIONAL_HEADER.ImageBase + symbol.address),
                        name=symbol.name,
                        ordinal=symbol.ordinal))
            self.results['exports'] = exports

            # get export module name
            section = self.pe.get_section_by_rva(self.pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
            offset = section.get_offset_from_rva(self.pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
            self.pe.ModuleName = self.pe.__data__[offset:offset + self.pe.__data__[offset:].find(chr(0))]
            self.results['exports_module_Name'] = safe_str(self.pe.ModuleName)
            self.results['exports_timestamp'] = time.ctime(self.pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp)

    def entrypoint(self):
        self.results['info']['entrypoint'] = hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def compiletime(self):
        self.results['info']['compiletime'] = {
            'unix': self.pe.FILE_HEADER.TimeDateStamp,
            'datetime': '{}'.format(datetime.datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp))
        }

    def peid(self):

        self.results['peid'] = []

        def get_signatures():

            with open(self.peid_db, 'rt', encoding='ISO-8859-1') as f:
                sig_data = f.read()

            return peutils.SignatureDatabase(data=sig_data)

        def get_matches(pe, signatures):
            matches = signatures.match_all(pe, ep_only=True)
            return matches

        peid_matches = get_matches(self.pe, get_signatures())

        if peid_matches:
            for sig in peid_matches:
                if type(sig) is list:
                    self.results['peid'].append(sig[0])
                else:
                    self.results['peid'].append(sig)
        else:
            self.results['peid'].append("No PEiD signatures matched.")

    def resources(self):
        self.results['resources'] = []

        # Use this function to retrieve resources for the given PE instance.
        # Returns all the identified resources with indicators and attributes.
        def get_resources(pe):
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                count = 1
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        resource = {}

                        if resource_type.name is not None:
                            name = str(resource_type.name)
                        else:
                            name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id, "UNKNOWN"))

                        if name is None:
                            name = str(resource_type.struct.Id)

                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                           resource_lang.data.struct.Size)
                                        entropy = get_entropy(data)
                                        filetype = get_type(data)
                                        md5 = get_md5(data)
                                        sha256 = get_sha256(data)
                                        language = pefile.LANG.get(resource_lang.data.lang, None)
                                        language_desc = LCID.get(resource_lang.id, 'unknown language')
                                        sublanguage = pefile.get_sublang_name_for_lang(
                                            resource_lang.data.lang, resource_lang.data.sublang)
                                        offset = ('%-8s' % hex(resource_lang.data.struct.OffsetToData)).strip()
                                        size = ('%-8s' % hex(resource_lang.data.struct.Size)).strip()

                                        resource = [
                                            count, name, offset, md5, sha256, size, filetype, entropy, language,
                                            sublanguage, language_desc
                                        ]

                                        # Dump resources if requested
                                        if self.dump and pe == self.pe:
                                            if self.dump:
                                                folder = self.dump
                                            else:
                                                folder = tempfile.mkdtemp()

                                            resource_path = path.join(folder, '{0}_{1}_{2}'.format(
                                                self.sha256, offset, name))
                                            resource.append(resource_path)

                                            with open(resource_path, 'wb') as resource_handle:
                                                resource_handle.write(data)

                                        resources.append(resource)

                                        count += 1
                    except Exception as e:
                        log.error(e)
                        continue

            return resources

        # Obtain resources for the currently opened file.
        resources = get_resources(self.pe)

        if not resources:
            log.warning("No resources found")
            return

        for resource in resources:
            self.results['resources'].append({
                'id': resource[0],
                'name': resource[1],
                'offset': resource[2],
                'md5': resource[3],
                'sha256': resource[4],
                'size': resource[5],
                'type': resource[6],
                'entropy': resource[7],
                'language': resource[8],
                'sublanguage': resource[9],
                'language_desc': resource[10],
            })

    def resource_versioninfo(self):
        if hasattr(self.pe, 'FileInfo'):
            pe_resource_verinfo_res_list = []
            for file_info in self.pe.FileInfo:
                if not isinstance(file_info, Iterable):
                    file_info = [file_info]
                for info in file_info:
                    pe_resource_verinfo_res = {}
                    if info.name == "StringFileInfo":
                        if len(info.StringTable) > 0:
                            lang_id = "0"
                            try:
                                if "LangID" in info.StringTable[0].entries:
                                    lang_id = info.StringTable[0].get("LangID")
                                    if not int(lang_id, 16) >> 16 == 0:
                                        pe_resource_verinfo_res['lang_id'] = '{} ({})'.format(
                                            lang_id, LCID[int(lang_id, 16) >> 16])
                                    else:
                                        pe_resource_verinfo_res['lang_id'] = "{} (NEUTRAL)".format(lang_id)
                            except (ValueError, KeyError):
                                pe_resource_verinfo_res['lang_id'] = '{} is invalid'.format(lang_id)

                            for entry in info.StringTable[0].entries.items():
                                if entry[0] == 'OriginalFilename':
                                    pe_resource_verinfo_res['original_filename'] = entry[1]
                                elif entry[0] == 'FileDescription':
                                    pe_resource_verinfo_res['file_description'] = entry[1]
                                else:
                                    if len(entry[1]) > 0:
                                        pe_resource_verinfo_res[entry[0].lower()] = entry[1]
                        pe_resource_verinfo_res_list.append(pe_resource_verinfo_res)
            if len(pe_resource_verinfo_res_list) > 1:
                self.results['resource_versioninfo'] = pe_resource_verinfo_res_list
            else:
                self.results['resource_versioninfo'] = pe_resource_verinfo_res_list[0]

    def resource_strings(self):
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

        ITEM_TYPES = {
            0x80: "BUTTON",
            0x81: "EDIT",
            0x82: "STATIC",
            0x83: "LIST BOX",
            0x84: "SCROLL BAR",
            0x85: "COMBO BOX"
        }

        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            tags = []
            for dir_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
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
                            data = self.pe.get_memory_mapped_image()[data_rva:data_rva + size]

                            offset = 0
                            if self.pe.get_word_at_rva(data_rva + offset) == 0x1 \
                                    and self.pe.get_word_at_rva(data_rva + offset + WORD) == 0xFFFF:
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
                                window_title = self.pe.get_string_u_at_rva(data_rva + offset)
                                if len(window_title) != 0:
                                    strings.append(("DIALOG_TITLE", window_title))
                                offset += len(window_title) * 2 + WORD

                                # Remove trailing bytes
                                offset += DIALOGEX_TRAIL
                                offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                # alignment adjustment
                                if (offset % 4) != 0:
                                    offset += WORD

                                while True:

                                    if offset >= size:
                                        break

                                    offset += DIALOGEX_ITEM_LEAD

                                    # Get item type
                                    if self.pe.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                        offset += WORD
                                        item_type = ITEM_TYPES[self.pe.get_word_at_rva(data_rva + offset)]
                                        offset += WORD
                                    else:
                                        item_type = self.pe.get_string_u_at_rva(data_rva + offset)
                                        offset += len(item_type) * 2 + WORD

                                    # Get item text
                                    item_text = self.pe.get_string_u_at_rva(data_rva + offset)
                                    if len(item_text) != 0:
                                        strings.append((item_type, item_text))
                                    offset += len(item_text) * 2 + WORD

                                    extra_bytes = self.pe.get_word_at_rva(data_rva + offset)
                                    offset += extra_bytes + DIALOGEX_ITEM_TRAIL

                                    # Alignment adjustment
                                    if (offset % 4) != 0:
                                        offset += WORD

                            else:
                                # TODO: Use Non extended Dialog Parsing
                                # Remove leading bytes
                                style = self.pe.get_word_at_rva(data_rva + offset)

                                offset += DIALOG_LEAD
                                if data[offset:offset + 2] == "\xFF\xFF":
                                    offset += DWORD
                                else:
                                    offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD
                                if data[offset:offset + 2] == "\xFF\xFF":
                                    offset += DWORD
                                else:
                                    offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                # Get window title
                                window_title = self.pe.get_string_u_at_rva(data_rva + offset)
                                if len(window_title) != 0:
                                    strings.append(("DIALOG_TITLE", window_title))
                                offset += len(window_title) * 2 + WORD

                                if (style & DS_SETFONT) != 0:
                                    offset += WORD
                                    offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                # Alignment adjustment
                                if (offset % 4) != 0:
                                    offset += WORD

                                while True:

                                    if offset >= size:
                                        break

                                    offset += DIALOG_ITEM_LEAD

                                    # Get item type
                                    if self.pe.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                        offset += WORD
                                        item_type = ITEM_TYPES[self.pe.get_word_at_rva(data_rva + offset)]
                                        offset += WORD
                                    else:
                                        item_type = self.pe.get_string_u_at_rva(data_rva + offset)
                                        offset += len(item_type) * 2 + WORD

                                    # Get item text
                                    if self.pe.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                        offset += DWORD
                                    else:
                                        item_text = self.pe.get_string_u_at_rva(data_rva + offset)
                                        if len(item_text) != 0:
                                            strings.append((item_type, item_text))
                                        offset += len(item_text) * 2 + WORD

                                    extra_bytes = self.pe.get_word_at_rva(data_rva + offset)
                                    offset += extra_bytes + WORD

                                    # Alignment adjustment
                                    if (offset % 4) != 0:
                                        offset += WORD

                        elif str(dir_type.name) == "RT_STRING":
                            data_rva = language.data.struct.OffsetToData
                            size = language.data.struct.Size
                            data = self.pe.get_memory_mapped_image()[data_rva:data_rva + size]
                            offset = 0
                            while True:
                                if offset >= size:
                                    break

                                ustr_length = self.pe.get_word_from_data(data[offset:offset + 2], 0)
                                offset += 2

                                if ustr_length == 0:
                                    continue

                                ustr = self.pe.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
                                offset += ustr_length * 2
                                strings.append((None, ustr))

                        if len(strings) > 0:
                            success = False
                            try:
                                comment = "%s (id:%s - lang_id:0x%04X [%s])" % (str(dir_type.name), str(nameID.name),
                                                                                language.id, LCID[language.id])
                            except KeyError:
                                comment = "%s (id:%s - lang_id:0x%04X [Unknown language])" % (str(
                                    dir_type.name), str(nameID.name), language.id)
                            log.debug("PE: STRINGS - %s" % comment)
                            for idx in range(len(strings)):
                                # noinspection PyBroadException
                                try:
                                    tag_value = strings[idx][1]

                                    # The following line crash chardet if a
                                    # UPX packed file as packed the resources...
                                    chardet.detect(tag_value)  # TODO: Find a better way to do this

                                    tag_value = tag_value.replace('\r', ' ').replace('\n', ' ')
                                    if strings[idx][0] is not None:
                                        tags.append(strings[idx][0])
                                        # res.add_line(
                                        #     [strings[idx][0], ": ",
                                        #      res_txt_tag(tag_value, TAG_TYPE['FILE_STRING'])])
                                    else:
                                        tags.append(tag_value)
                                        # res.add_line(res_txt_tag(tag_value, TAG_TYPE['FILE_STRING']))

                                    success = True
                                except:
                                    pass
                            if success:
                                self.results['resource_strings'] = tags

    def slack_space(self):
        if self.results['info']['calculated_file_size'] > 0 and (len(self.pe.__data__) >
                                                                 self.results['info']['calculated_file_size']):
            slack_size = len(self.pe.__data__) - self.results['info']['calculated_file_size']
            if self.dump:
                slack_path = path.join(self.dump, '{}_slack.bin'.format(self.sha256))
                with open(slack_path, 'wb') as shandle:
                    shandle.write(self.pe.__data__[self.results['info']['calculated_file_size']:
                                                   self.results['info']['calculated_file_size'] + slack_size])

    def imphash(self):
        self.results['imphash'] = self.pe.get_imphash()

    def security(self):
        pass
        # def get_certificate(pe):
        #     # TODO: this only extract the raw list of certificate data.
        #     # I need to parse them, extract single certificates and perhaps return
        #     # the PEM data of the first certificate only.
        #     pe_security_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        #     address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pe_security_dir].VirtualAddress
        #     #  size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pe_security_dir].Size

        #     if address:
        #         return pe.write()[address + 8:]
        #     else:
        #         return None

        # cert_data = get_certificate(self.pe)

        # if not cert_data:
        #     log.warning("No certificate found")
        #     return

        # cert_sha256 = sha256_checksum(cert_data)

        # if self.args.dump:
        #     cert_path = path.join(self.args.dump, '{0}.crt'.format(cert_sha256))
        #     with open(cert_path, 'wb+') as cert_handle:
        #         cert_handle.write(cert_data)

        #     log.info("Dumped certificate to {0}".format(cert_path))
        #     log.info(
        #         "You can parse it using the following command:\n\topenssl pkcs7 -inform DER -print_certs -text -in {0}".
        #         format(cert_path))

        # # TODO: this function needs to be better integrated with the rest of the command.
        # # TODO: need to add more error handling and figure out why so many samples are failing.
        # if self.args.check:

        #     try:
        #         auth, computed_content_hash = get_auth_data(__sessions__.current.file.path)
        #     except Exception as e:
        #         self.log('error', "Unable to parse PE certificate: {0}".format(str(e)))
        #         return

        #     try:
        #         auth.ValidateAsn1()
        #         auth.ValidateHashes(computed_content_hash)
        #         auth.ValidateSignatures()
        #         auth.ValidateCertChains(time.gmtime())
        #     except Exception as e:
        #         self.log('error', "Unable to validate PE certificate: {0}".format(str(e)))
        #         return

        #     self.log('info', bold('Signature metadata:'))
        #     self.log('info', 'Program name: {0}'.format(auth.program_name))
        #     self.log('info', 'URL: {0}'.format(auth.program_url))

        #     if auth.has_countersignature:
        #         self.log(
        #             'info',
        #             bold('Countersignature is present. Timestamp: {0} UTC'.format(
        #                 time.asctime(time.gmtime(auth.counter_timestamp)))))
        #     else:
        #         self.log('info', bold('Countersignature is not present.'))

        #     self.log('info', bold('Binary is signed with cert issued by:'))
        #     self.log('info', '{0}'.format(auth.signing_cert_id[0]))

        #     self.log('info', '{0}'.format(auth.cert_chain_head[2][0]))
        #     self.log('info', 'Chain not before: {0} UTC'.format(time.asctime(time.gmtime(auth.cert_chain_head[0]))))
        #     self.log('info', 'Chain not after: {0} UTC'.format(time.asctime(time.gmtime(auth.cert_chain_head[1]))))

        #     if auth.has_countersignature:
        #         self.log('info', bold('Countersig chain head issued by:'))
        #         self.log('info', '{0}'.format(auth.counter_chain_head[2]))
        #         self.log('info', 'Countersig not before: {0} UTC'.format(
        #             time.asctime(time.gmtime(auth.counter_chain_head[0]))))
        #         self.log('info', 'Countersig not after: {0} UTC'.format(
        #             time.asctime(time.gmtime(auth.counter_chain_head[1]))))

        #     self.log('info', bold('Certificates:'))
        #     for (issuer, serial), cert in auth.certificates.items():
        #         self.log('info', 'Issuer: {0}'.format(issuer))
        #         self.log('info', 'Serial: {0}'.format(serial))
        #         subject = cert[0][0]['subject']
        #         subject_dn = str(dn.DistinguishedName.TraverseRdn(subject[0]))
        #         self.log('info', 'Subject: {0}'.format(subject_dn))
        #         not_before = cert[0][0]['validity']['notBefore']
        #         not_after = cert[0][0]['validity']['notAfter']
        #         not_before_time = not_before.ToPythonEpochTime()
        #         not_after_time = not_after.ToPythonEpochTime()
        #         self.log('info', 'Not Before: {0} UTC ({1})'.format(
        #             time.asctime(time.gmtime(not_before_time)), not_before[0]))
        #         self.log('info', 'Not After: {0} UTC ({1})'.format(
        #             time.asctime(time.gmtime(not_after_time)), not_after[0]))

        #     if auth.trailing_data:
        #         self.log(
        #             'info', 'Signature Blob had trailing (unvalidated) data ({0} bytes): {1}'.format(
        #                 len(auth.trailing_data), auth.trailing_data.encode('hex')))

    def language(self):

        def get_iat(pe):
            iat = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for peimport in pe.DIRECTORY_ENTRY_IMPORT:
                    iat.append(peimport.dll)

            return iat

        def check_module(iat, match):
            for imp in iat:
                if imp.find(match) != -1:
                    return True

            return False

        def is_cpp(data, cpp_count):
            for line in data:
                if b'type_info' in line or b'RTTI' in line:
                    cpp_count += 1
                    break

            if cpp_count == 2:
                return True

            return False

        def is_delphi(data):
            for line in data:
                if b'Borland' in line:
                    path = line.split(b'\\')
                    for p in path:
                        if b'Delphi' in p:
                            return True
            return False

        def is_vbdotnet(data):
            for line in data:
                if b'Compiler' in line:
                    stuff = line.split(b'.')
                    if b'VisualBasic' in stuff:
                        return True

            return False

        def is_autoit(data):
            for line in data:
                if b'AU3!' in line:
                    return True

            return False

        def is_packed(pe):
            for section in pe.sections:
                if section.get_entropy() > 7:
                    return True

            return False

        def get_strings(content):
            regexp = b'[\x30-\x39\x41-\x5f\x61-\x7a\-\.:]{4,}'
            return re.findall(regexp, content)

        def find_language(iat, sample, content):
            dotnet = False
            cpp_count = 0
            found = None

            # VB check
            if check_module(iat, 'VB'):
                log('info', "{0} - Possible language: Visual Basic".format(sample.name))
                return 'Visual Basic'

            # .NET check
            if check_module(iat, 'mscoree.dll') and not found:
                dotnet = True
                found = '.NET'

            # C DLL check
            if not found and (check_module(iat, 'msvcr') or check_module(iat, 'MSVCR') or check_module(iat, 'c++')):
                cpp_count += 1

            if not found:
                data = get_strings(content)

                if is_cpp(data, cpp_count) and not found:
                    found = 'CPP'
                if not found and cpp_count == 1:
                    found = 'C'
                if not dotnet and is_delphi(data) and not found:
                    found = 'Delphi'
                if dotnet and is_vbdotnet(data):
                    found = 'Visual Basic .NET'
                if is_autoit(data) and not found:
                    found = 'AutoIt'

            return found

        self.results['is_packed'] = is_packed(self.pe)
        if self.results['is_packed']:
            log.warning("Probably packed, the language guess might be unreliable")

        self.results['language'] = find_language(get_iat(self.pe), self.file, self.data)

    def sections(self):
        sections = []
        for section in self.pe.sections:
            if isinstance(section.Name, bytes):
                section_name = section.Name.decode()
            else:
                section_name = safe_str(section.Name)
            section_name = section_name.replace('\x00', '')
            # if self.dump:
            #     file_handle = BytesIO(self.data)
            #     file_handle.seek(int(section.PointerToRawData))
            #     section_data = file_handle.read(int(section.SizeOfRawData))
            #
            #     dump_path = path.join(self.dump, '{}_{}.bin'.format(self.sha256, section_name))
            #     with open(dump_path, 'wb') as dump_handle:
            #         dump_handle.write(section_data)

            # calculated file size
            self.results['info']['calculated_file_size'] = int(section.VirtualAddress) + int(section.Misc_VirtualSize)

            sections.append({
                'name': section_name,
                'rva': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'pointer_to_raw_data': section.PointerToRawData,
                'raw_data_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
                'md5': section.get_hash_md5(),
            })

        self.results['sections'] = sections

    def pehash(self):
        self.results['pehash'] = calculate_pehash(self.file)

    def triage(self):
        pass

    def run(self):

        try:
            # get cert info
            self.results['signature'] = get_signify(self.file, log=log)

            self.pe = pefile.PE(self.file)
            # print(self.pe.dump_info())

            # run all the analysis
            self.info()
            self.debug()
            self.imports()
            self.exports()
            self.resources()
            self.resource_versioninfo()
            self.resource_strings()
            self.imphash()
            self.compiletime()
            self.peid()
            self.security()
            self.sections()
            self.language()
            self.pehash()
            self.entrypoint()
            self.slack_space()

        except pefile.PEFormatError as e:
            log.error("Unable to parse PE file: {0}".format(e))
            if e.value != "DOS Header magic not found.":
                self.results['error'] = "this file looks like a PE but failed loading inside PE file. [", e.value, "]"
        except Exception as e:
            log.exception(e)

        return self.results
