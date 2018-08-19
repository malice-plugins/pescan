import logging
import traceback

import signify
from signify import signed_pe


def get_signify(file_handle, res=None, log=None):

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
        # res.add_section(ResultSection(SCORE.OK, "This file is signed"))
        # res.report_heuristic(PEFile.AL_PEFile_002)

    except signify.exceptions.SignedPEParseError as e:
        if e.message == "The PE file does not contain a certificate table.":
            pass
            # res.add_section(ResultSection(SCORE.NULL, "No file signature data found"))

        else:
            pass
            # res.add_section(ResultSection(SCORE.NULL, "Unknown exception. Traceback: %s" % traceback.format_exc()))

    except signify.exceptions.AuthenticodeVerificationError as e:
        if e.message == "The expected hash does not match the digest in SpcInfo":
            pass
            # This sig has been copied from another program
            # res.add_section(ResultSection(SCORE.HIGH, "The signature does not match the program data"))
            # res.report_heuristic(PEFile.AL_PEFile_001)
        else:
            pass
            # res.add_section(
            #     ResultSection(SCORE.NULL, "Unknown authenticode exception. Traceback: %s" % traceback.format_exc()))

    except signify.exceptions.VerificationError as e:
        if e.message.startswith("Chain verification from"):
            pass
            # probably self signed
            # res.add_section(ResultSection(SCORE.MED, "File is self-signed"))
            # res.report_heuristic(PEFile.AL_PEFile_003)
        else:
            pass
            # res.add_section(ResultSection(SCORE.NULL, "Unknown exception. Traceback: %s" % traceback.format_exc()))

    # Now try to get certificate and signature data
    sig_datas = []
    try:
        sig_datas.extend([x for x in s_data.signed_datas])
    except:
        pass

    if len(sig_datas) > 0:
        # Now extract certificate data from the sig
        for s in sig_datas:
            pass
            # Extract signer info. This is probably the most useful?
            # res.add_tag(TAG_TYPE.CERT_SERIAL_NO, str(s.signer_info.serial_number))
            # res.add_tag(TAG_TYPE.CERT_ISSUER, s.signer_info.issuer_dn)

            # Get cert used for signing, then add valid from/to info
            for cert in [x for x in s.certificates if x.serial_number == s.signer_info.serial_number]:
                pass
                # res.add_tag(TAG_TYPE.CERT_SUBJECT, cert.subject_dn)
                # res.add_tag(TAG_TYPE.CERT_VALID_FROM, cert.valid_from.isoformat())
                # res.add_tag(TAG_TYPE.CERT_VALID_TO, cert.valid_to.isoformat())

            for cert in s.certificates:
                cert_res = []  # ResultSection(SCORE.NULL, "Certificate Information")
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
                cert_res.append([
                    "CERT_VERSION: %d" % cert.version,
                    "CERT_SERIAL_NO: %d" % cert.serial_number,
                    "CERT_ISSUER: %s" % cert.issuer_dn,
                    "CERT_SUBJECT: %s" % cert.subject_dn,
                    "CERT_VALID_FROM: %s" % cert.valid_from.isoformat(),
                    "CERT_VALID_TO: %s" % cert.valid_to.isoformat()
                ])
                # cert_res.add_tag(TAG_TYPE.CERT_VERSION, str(cert.version))
                # cert_res.add_tag(TAG_TYPE.CERT_SERIAL_NO, str(cert.serial_number))
                # cert_res.add_tag(TAG_TYPE.CERT_ISSUER, cert.issuer_dn)
                # cert_res.add_tag(TAG_TYPE.CERT_VALID_FROM, cert.valid_from.isoformat())
                # cert_res.add_tag(TAG_TYPE.CERT_VALID_TO, cert.valid_to.isoformat())
                # cert_res.add_tag(TAG_TYPE.CERT_SUBJECT, cert.subject_dn)

                # res.add_section(cert_res)
            print(cert_res)
    # pprint.pprint(file_res)
