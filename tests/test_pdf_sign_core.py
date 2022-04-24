import aiounittest
import unittest

from pypdfsign.core import generate_cert_pkey, sign_pdf 
from pypdfsign.core import text_stamp_style
from pypdfsign.core import cert_pk_to_signer

from fpdf import FPDF
from io import BytesIO

def fixture_pdf():
    pdf = FPDF()
    pdf.add_page()
    return BytesIO(pdf.output(dest="S").encode("latin-1"))
    

class SignPDFTest(aiounittest.AsyncTestCase):
    def setUp(self):
        (cert, pk) = generate_cert_pkey(
            email_address="foo@email.org",
            common_name="common",
            country_name="CN",
            locality_name="locality",
            state_or_province_name="state",
            organization_name="organization",
            organization_unit_name="organization_unit",
            serial_number=0
        )

        self.cert = cert
        self.pk = pk

    async def test_simple_sign(self):
        signer = cert_pk_to_signer((self.cert, self.pk))
        stamp_style = text_stamp_style("Signed by %(signer)\nTime: %(ts)")
        doc = fixture_pdf()
        signed = await sign_pdf(doc, signer, stamp_style, "Signature", (10, 10), (100, 100), 0)

if __name__ == "__main__":
    unittest.main()
