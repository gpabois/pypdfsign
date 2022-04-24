from OpenSSL import crypto, SSL

from pyhanko.sign import signers
from pyhanko import stamp
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

def generate_cert_pkey(email_address, common_name, country_name, locality_name, state_or_province_name, organization_name, organization_unit_name, serial_number, validity_start_in_seconds=0, validity_end_in_seconds=5*365*24*60*60):
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

def save_cert_pk(pair, pair_path):
    cert = pair[0]
    pk = pair[1]
    cert_fp = pair_path[0]
    pk_fp = pair_path[1]

    with open(cert_fp, "wt") as f:
        f.write(crypto.dump_certificate(crypto_FILETYPE_PEM, cert).decode("utf-8"))

    with open(pk_f, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk).decode("utf-8"))

def cert_pk_to_signer(cert_pk_pair):
    (cert, pk) = cert_pk_pair
    return signers.SimpleSigner.load(pk, cert)

def text_stamp_style(text, box_style=None, background=None):
    stamp.TextStampStyle(
        stamp_text=text,
        text_box_style=box_style,
        background=background
    )

async def sign_pdf(pdf_doc, signer, stamp_style, field_name, pos, size, page, **metadata):
    w = IncrementalPdfFileWriter(pdf_doc)
    (x, y) = pos
    (h, w) = size
    box = (x, x+w, y, y+w)
    append_signature_field(w, sig_field_spec=SigFieldSpec(field_name, box=box, on_page=page))
    out = await signers.async_sign_pdf(w, 
            signers.PDFSignatureMetadata(field_name=field_name, **metadata),
            signer=signer,
            stamp_style=stamp_style)
    return out
