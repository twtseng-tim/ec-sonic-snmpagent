import os
import sys

modules_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(modules_path, 'src'))

from unittest import TestCase

# noinspection PyUnresolvedReferences
import tests.mock_tables.dbconnector

from ax_interface.mib import MIBTable
from ax_interface.pdu import PDUHeader
from ax_interface.pdu_implementations import GetPDU, GetNextPDU
from ax_interface import ValueType
from ax_interface.encodings import ObjectIdentifier
from ax_interface.constants import PduTypes
from sonic_ax_impl.mibs.ietf import rfc4363
from sonic_ax_impl.main import SonicMIB
from swsssdk.port_util import BaseIdx

class TestSonicMIB(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lut = MIBTable(SonicMIB)
        for updater in cls.lut.updater_instances:
            updater.update_data()
            updater.reinit_data()
            updater.update_data()

    def test_getpdu(self):
        oid = ObjectIdentifier(20, 0, 0, 0, (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1, 11))
        get_pdu = GetPDU(
            header=PDUHeader(1, PduTypes.GET, 16, 0, 42, 0, 0, 0),
            oids=[oid]
        )

        encoded = get_pdu.encode()
        response = get_pdu.make_response(self.lut)
        print(response)

        value0 = response.values[0]
        self.assertEqual(value0.type_, ValueType.INTEGER)
        self.assertEqual(str(value0.name), str(oid))
        self.assertEqual(value0.data, 10)

    def test_getnextpdu(self):
        get_pdu = GetNextPDU(
            header=PDUHeader(1, PduTypes.GET, 16, 0, 42, 0, 0, 0),
            oids=(
                ObjectIdentifier(20, 0, 0, 0, (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1, 10)),
            )
        )

        encoded = get_pdu.encode()
        response = get_pdu.make_response(self.lut)
        print(response)

        n = len(response.values)
        value0 = response.values[0]
        self.assertEqual(value0.type_, ValueType.INTEGER)
        self.assertEqual(value0.data, 10)

    def test_getnextpdu_lag(self):
        get_pdu = GetNextPDU(
            header=PDUHeader(1, PduTypes.GET, 16, 0, 42, 0, 0, 0),
            oids=(
                ObjectIdentifier(20, 0, 0, 0, (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1, 1000)),
            )
        )

        response = get_pdu.make_response(self.lut)

        value0 = response.values[0]
        self.assertEqual(value0.type_, ValueType.INTEGER)
        self.assertEqual(value0.data, 10)

    def test_getnextpdu_exactmatch(self):
        # oid.include = 1
        oid = ObjectIdentifier(20, 0, 1, 0, (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1, 11))
        get_pdu = GetNextPDU(
            header=PDUHeader(1, PduTypes.GET, 16, 0, 42, 0, 0, 0),
            oids=[oid]
        )

        encoded = get_pdu.encode()
        response = get_pdu.make_response(self.lut)
        print(response)

        n = len(response.values)
        value0 = response.values[0]
        self.assertEqual(value0.type_, ValueType.INTEGER)
        print("test_getnextpdu_exactmatch: ", str(oid))
        self.assertEqual(str(value0.name), str(oid))
        self.assertEqual(value0.data, 10)

    def test_getpdu_noinstance(self):
        get_pdu = GetPDU(
            header=PDUHeader(1, PduTypes.GET, 16, 0, 42, 0, 0, 0),
            oids=(
                ObjectIdentifier(20, 0, 0, 0, (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1, 100)),
            )
        )

        encoded = get_pdu.encode()
        response = get_pdu.make_response(self.lut)
        print(response)

        n = len(response.values)
        value0 = response.values[0]
        self.assertEqual(value0.type_, ValueType.NO_SUCH_INSTANCE)

    def test_getnextpdu_empty(self):
        get_pdu = GetNextPDU(
            header=PDUHeader(1, PduTypes.GET, 16, 0, 42, 0, 0, 0),
            oids=(
                ObjectIdentifier(20, 0, 0, 0, (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 2)),
            )
        )

        encoded = get_pdu.encode()
        response = get_pdu.make_response(self.lut)
        print(response)

        n = len(response.values)
        value0 = response.values[0]
        self.assertEqual(value0.type_, ValueType.END_OF_MIB_VIEW)
