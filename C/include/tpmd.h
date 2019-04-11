/*
 * tpmd.h
 *
 * Copyright (C) 2019 Dream Property GmbH, Germany
 *                    https://dreambox.de/
 *
 * The permission notice below applies to this file only:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _TPMD_H_
#define _TPMD_H_

#define TPMD_SOCKET "/var/run/tpmd_socket"

/*
 * Commands are TLV-encoded. Tag and length field are 16 bits wide.
 */

/* 16 bits */
enum tpmd_cmd {
	TPMD_CMD_RESERVED		= 0x0000,
	TPMD_CMD_GET_DATA		= 0x0001,	/* TPM V1+V2 (V2: limited to reading versions and serial) */
	TPMD_CMD_APDU			= 0x0002,	/* TPM V1 */
	TPMD_CMD_COMPUTE_SIGNATURE	= 0x0003,	/* TPM V1+V2 */
	TPMD_CMD_APP_CERT		= 0x0004,	/* TPM V1 */
	TPMD_CMD_GET_DATA_V2		= 0x0011,	/* TPM V1+V2 */
};

/*
 * TPMD_CMD_GET_DATA is used to request data types from the TPMD,
 * such as protocol version and hardware details.
 *
 * TAG = 0x0001
 * LEN = variable
 * VAL = tpmd_data_type, [...]
 *
 * example:
 * 00 01 00 03 01 01 02
 *
 * Encoding of VAL is [dt li ...] for TPMD_CMD_GET_DATA and [dt li li ...] for
 * TPMD_CMD_GET_DATA_V2.
 *
 * example:
 * 00 11 00 02 01 00 01 02
 */

/* 8 bits */
enum tpmd_data_type_tag {
	TPMD_DT_RESERVED		= 0x00,
	TPMD_DT_PROTOCOL_VERSION	= 0x01, /* LEN = 1 */
	TPMD_DT_TPM_VERSION		= 0x02, /* LEN = 1 */
	TPMD_DT_SERIAL			= 0x03, /* LEN = 4 */
	TPMD_DT_LEVEL2_CERT		= 0x04, /* LEN = 210 (V1) / variable (V2) */
	TPMD_DT_LEVEL3_CERT		= 0x05, /* LEN = 210 (V1) / variable (V2) */
	TPMD_DT_FAB_CA_CERT		= 0x06,	/* LEN = 210 (V1) / variable (V2) */
	TPMD_DT_DATABLOCK_SIGNED	= 0x07,	/* LEN = 128 (V1) / 256 (V2) */
};

/*
 * The protocol version indicates available features. An application
 * should always check for its own minimum requirements. Higher protocol
 * versions will remain backwards compatible.
 *
 * TPMD_API_VERSION may be used for conditional compilation. It was introduced
 * with protocol version 3.
 */

/* 8 bits */
enum tpmd_protocol_version {
	TPMD_PV_UNKNOWN			= 0x00,
	/* Initial release */
	TPMD_PV_1			= 0x01,
	/* Introduction of TPMD_CMD_APP_CERT */
	TPMD_PV_2			= 0x02,
	/* Introduction of TPMD_CMD_GET_DATA_V2 */
	TPMD_PV_3			= 0x03,
#define TPMD_API_VERSION TPMD_PV_3
};

/*
 * The TPM version indicates the type of underlying security hardware,
 * which has different control requirements. An application must not
 * assume that it can handle an unknown version.
 */

/* 8 bits */
enum tpmd_tpm_version {
	TPMD_TV_UNKNOWN			= 0x00,
	TPMD_TV_1			= 0x01,
	TPMD_TV_2			= 0x02,
};

/*
 * TPMD_CMD_APDU sends a raw ISO7816 APDU to the TPM.
 *
 * TAG = 0x0002
 * LEN = variable
 * VAL = Flags + ISO7816 APDU
 *
 * flags: enum tpmd_apdu_flags
 * cla, ins, p1, p2, len, data: see ISO7816
 *
 * example:
 * 00 02 li li flags cla ins p1 p2 len data...
 *
 */

enum tpmd_apdu_flags {
	TPMD_APDU_READ			= (1 << 0),
	TPMD_APDU_WRITE			= (1 << 1),
};

#endif /* _TPMD_H_ */
