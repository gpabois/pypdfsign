from OpenSSL import crypto, SSL

from pyhanko.sign import signers
from pyhanko import stamp
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

def gen_cert(email_address, 
    common_name, 
    country_name, 
    locality_name, 
    state_or_province_name, 
    organization_name, 
    organization_unit_name, 
    serial_number, 
    validity_start_in_seconds=0, 
    validity_end_in_seconds=5*365*24*60*60):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    cert = crypto.X509()
    cert.get_subject().C = country_name
    cert.get_subject().ST = state_or_province_name
    cert.get_subject().L = locality_name
    cert.get_subject().O = organization_name
    cert.get_subject().OU = organization_unit_name
    cert.get_subject().CN = common_name
    cert.get_subject().emailAddress = email_address
    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(validity_start_in_seconds)
    cert.gmtime_adj_notAfter(validity_end_in_seconds)
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    return (cert, k)

def dump_cert(pair):
    (cert, pk) = pair
    return (crypto.dump_certificate(crypto_FILETYPE_PEM, cert).decode("utf-8"), crypto.dump_privatekey(crypto.FILETYPE_PEM, pk).decode("utf-8"))
