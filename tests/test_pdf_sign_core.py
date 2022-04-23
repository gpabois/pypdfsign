import aiounittest
import unittest

from pypdfsign.core import generate_cert_pkey, sign_pdf 

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
        pass


if __name__ == "__main__":
    unittest.main()
