#!/usr/bin/env python
#
# Copyright (C) 2019 Dream Property GmbH, Germany
#                    https://dreambox.de/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

"""
This class exists for demonstrational purposes only. On a Dreambox, enigma2
provides its own implementation. You don't need to include it in your project.
"""

class eTPM():
    _TPMD_SOCKET = '/var/run/tpmd_socket'

    _TPMD_CMD_GET_DATA = 0x01
    _TPMD_CMD_COMPUTE_SIGNATURE = 0x03
    _TPMD_CMD_GET_DATA_V2 = 0x11

    DT_PROTOCOL_VERSION = 0x01
    DT_TPM_VERSION = 0x02
    DT_LEVEL2_CERT = 0x04
    DT_LEVEL3_CERT = 0x05


    def __init__(self):
        self._socket = self._connect()
        self._protocol_version = None
        self._tpm_version = None


    def getData(self, data_type):
        if self._protocol_version is None and data_type != self.DT_PROTOCOL_VERSION:
            self.getData(self.DT_PROTOCOL_VERSION)

        buf = bytearray()
        buf.append(data_type)

        if self._protocol_version is None or self._protocol_version < 3:
            cmd_get_data = self._TPMD_CMD_GET_DATA
        else:
            cmd_get_data = self._TPMD_CMD_GET_DATA_V2

        data = self._cmd(cmd_get_data, buf)

        assert(len(data) >= 2)
        assert(int(data[0]) == data_type)

        if self._protocol_version is None or self._protocol_version < 3:
            count = data[1]
            offset = 2
        else:
            assert(len(data) >= 3)
            count = (data[1] << 8) | data[2]
            offset = 3

        assert(len(data) == offset + count)
        payload = data[offset:]

        if data_type == self.DT_PROTOCOL_VERSION:
            assert(len(payload) == 1)
            self._protocol_version = payload[0]
        elif data_type == self.DT_TPM_VERSION:
            assert(len(payload) == 1)
            self._tpm_version = payload[0]

        return payload


    def computeSignature(self, plaintext):
        if not self._tpm_version:
            self.getData(self.DT_TPM_VERSION)

        return self._cmd(self._TPMD_CMD_COMPUTE_SIGNATURE, plaintext)


    def _connect(self):
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self._TPMD_SOCKET)
        return s


    def _send_cmd(self, cmd, data):
        header = bytearray()
        header.append((cmd >> 8) & 0xff)
        header.append((cmd >> 0) & 0xff)
        header.append((len(data) >> 8) & 0xff)
        header.append((len(data) >> 0) & 0xff)
        self._socket.sendall(header + data)


    def _recv_cmd(self):
        buf = bytearray(self._socket.recv(4))
        cmd = (buf[0] << 8) | buf[1]
        count = (buf[2] << 8) | buf[3]
        data = bytearray(self._socket.recv(count))
        assert(len(data) == count)
        return cmd, data


    def _cmd(self, cmd, data):
        self._send_cmd(cmd, data)
        rcmd, rdata = self._recv_cmd()
        assert(rcmd == cmd)
        return rdata
