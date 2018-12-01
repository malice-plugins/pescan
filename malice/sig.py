import logging
import traceback
from io import BytesIO, open

import signify
from signify import signed_pe


def get_signify(file_path, log=None):
    signature = {}
    s_data = None

    if log is None:
        log = logging.getLogger("get_signify")
    else:
        log = log.getChild("get_signify")

    try:
        file_handle = BytesIO(open(file_path, "rb").read())
        s_data = signed_pe.SignedPEFile(file_handle)
        # Now try checking for verification
        s_data.verify()

        # signature is verified
        signature['heuristic'] = "This PE appears to have a legitimate signature"

    except signify.exceptions.SignedPEParseError as e:
        if e.message == "The PE file does not contain a certificate table.":
            signature['heuristic'] = "No file signature data found"
        else:
            signature['error'] = e.message
            log.exception(e)

    except signify.exceptions.AuthenticodeVerificationError as e:
        if e.message == "The expected hash does not match the digest in SpcInfo":
            # This sig has been copied from another program
            signature['heuristic'] = "Signature data found in PE but doesn't match the program data. " + \
                                     "This is either due to malicious copying of signature data or an error in transmission."
        # res.report_heuristic(PEFile.AL_PEFile_001)
        else:
            signature['error'] = e.message
            log.exception(e)

    except signify.exceptions.VerificationError as e:
        if e.message.startswith("Chain verification from"):
            # probably self signed
            signature['heuristic'] = "This PE appears is self-signed"
        else:
            signature['error'] = e.message
            log.exception(e)

    except Exception as e:
        signature['error'] = e.message
        log.exception(e)

    # Now try to get certificate and signature data
    sig_datas = []
    try:
        if s_data is not None:
            sig_datas.extend([x for x in s_data.signed_datas])
    except:
        pass

    if len(sig_datas) > 0:
        signature['certs'] = []
        # Now extract certificate data from the sig
        for s in sig_datas:
            signature_data = {}

            # Get cert used for signing, then add valid from/to info
            signature_data['signer'] = []
            for cert in [x for x in s.certificates if x.serial_number == s.signer_info.serial_number]:
                signature_data['signer'].append({
                    "cert_version": cert.version,
                    "cert_serial_no": str(cert.serial_number),
                    "cert_issuer": cert.issuer_dn,
                    "cert_subject": cert.subject_dn,
                    "cert_valid_from": cert.valid_from.isoformat(),
                    "cert_valid_to": cert.valid_to.isoformat()
                })

            signature_data['other'] = []
            for cert in s.certificates:

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
                if cert.serial_number != s.signer_info.serial_number:
                    signature_data['other'].append({
                        "cert_version": cert.version,
                        "cert_serial_no": str(cert.serial_number),
                        "cert_issuer": cert.issuer_dn,
                        "cert_subject": cert.subject_dn,
                        "cert_valid_from": cert.valid_from.isoformat(),
                        "cert_valid_to": cert.valid_to.isoformat()
                    })

            signature['certs'].append(signature_data)
    return signature
