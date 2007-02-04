const unsigned char iwi_boot[] = {
	0x20,0x20,0x80,0x0F,0x00,0x00,0x40,0x00,0x69,0x20,0x00,0x00,
	0x69,0x20,0x40,0x00,0x69,0x20,0x00,0x00,0x69,0x20,0x40,0x00,
	0x20,0x20,0x80,0x0F,0x00,0x00,0xE8,0x00,0x69,0x20,0x00,0x00,
	0x69,0x20,0x40,0x00,0x69,0x20,0x00,0x00,0x69,0x20,0x40,0x00,
	0x20,0x20,0x80,0x0F,0x00,0x00,0xD0,0x01,0x69,0x20,0x00,0x00,
	0x69,0x20,0x40,0x00,0x69,0x20,0x00,0x00,0x4A,0x20,0x00,0x00,
	0x4A,0x21,0x00,0x00,0x4A,0x22,0x00,0x00,0x4A,0x23,0x00,0x00,
	0x4A,0x24,0x00,0x00,0x4A,0x25,0x00,0x00,0x4A,0x26,0x00,0x00,
	0x4A,0x27,0x00,0x00,0x4A,0x20,0x00,0x10,0x4A,0x21,0x00,0x10,
	0x4A,0x22,0x00,0x10,0x4A,0x23,0x00,0x10,0x4A,0x24,0x00,0x10,
	0x4A,0x25,0x00,0x10,0x4A,0x26,0x00,0x10,0x4A,0x27,0x00,0x10,
	0x4A,0x20,0x00,0x20,0x4A,0x21,0x00,0x20,0x4A,0x22,0x00,0x20,
	0x4A,0x23,0x00,0x20,0x4A,0x24,0x00,0x20,0x4A,0x25,0x00,0x20,
	0x4A,0x26,0x00,0x20,0x4A,0x27,0x00,0x20,0x4A,0x20,0x00,0x30,
	0x4A,0x21,0x00,0x30,0x0A,0x24,0x80,0x3F,0x80,0x00,0x00,0x80,
	0x41,0x2C,0x9C,0x30,0x40,0x2C,0x9C,0x30,0x42,0x24,0x1C,0x34,
	0x0A,0x22,0x80,0x3F,0x80,0x00,0x0C,0x3E,0x0A,0x23,0x00,0x37,
	0xD6,0x08,0x00,0x00,0x4A,0x26,0x00,0x70,0x69,0x20,0x40,0x00,
	0x4A,0x26,0x00,0x70,0x4A,0x26,0x00,0x70,0x4A,0x26,0x00,0x70,
	0x4A,0x26,0x00,0x70,0x42,0x08,0x00,0x00,0x20,0x20,0x40,0x87,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0xF8,0xC9,0xCF,0x72,0xA0,0x00,0xC8,0x1F,
	0x0E,0x1A,0x18,0x80,0xF9,0xC9,0x0F,0x1A,0x18,0x80,0xFA,0xC9,
	0x10,0x1A,0x18,0x80,0xFB,0x12,0x01,0xB6,0x16,0xC8,0x24,0x78,
	0x11,0x1A,0x18,0x80,0xE0,0x7E,0xE0,0x78,0xF1,0xC0,0xCF,0x70,
	0xA0,0x00,0xC8,0x1F,0x16,0x10,0x00,0x86,0xCF,0x71,0x80,0x00,
	0x20,0x00,0x04,0x20,0x80,0x8F,0xDE,0x57,0x04,0x80,0x01,0xA1,
	0x0A,0xF2,0x2F,0x29,0x01,0x00,0xCF,0x70,0x80,0x00,0x08,0x3F,
	0xF0,0x20,0x40,0x00,0x40,0x78,0xEB,0xFF,0xD1,0xC0,0xE0,0x7E,
	0x10,0xD8,0xF8,0x1A,0x18,0xB0,0x00,0xD8,0x9B,0xB8,0xF9,0x1A,
	0x18,0xB0,0x00,0xD8,0xFA,0x1A,0x18,0xB0,0x00,0xD8,0x8F,0xB8,
	0xFB,0x1A,0x18,0xB0,0xE0,0x7E,0xE0,0x78,0xF8,0xC9,0x9E,0xB8,
	0xF8,0x1A,0x18,0xB0,0xF9,0xC9,0x8D,0xB8,0x9B,0xB8,0xF9,0x1A,
	0x18,0xB0,0xFB,0xC9,0x05,0x20,0x80,0x0F,0x5E,0x04,0x00,0x00,
	0xFB,0x1A,0x18,0xB0,0xE0,0x7E,0xE0,0x78,0xF1,0xC0,0x36,0x0B,
	0x00,0x00,0xE2,0x08,0x00,0x00,0xEE,0x08,0x00,0x00,0x03,0xD9,
	0xCF,0x70,0x9F,0x00,0xD8,0xFF,0x2E,0xA0,0xEB,0x70,0xD0,0xD9,
	0xCF,0x72,0x80,0x00,0x38,0x35,0xFE,0xDB,0x1A,0x0D,0x20,0x00,
	0x98,0x71,0xD1,0xC0,0xE0,0x7E,0xE0,0x78,0xE1,0xC4,0xFC,0x1C,
	0x08,0xBF,0x6A,0x24,0x80,0x10,0xE1,0xC4,0x6A,0x24,0xC0,0x10,
	0xE1,0xC4,0xFC,0x1C,0xC8,0xBE,0xFC,0x1C,0x48,0xBE,0xE1,0xC0,
	0xE1,0xC1,0xE1,0xC2,0xE1,0xC3,0xFC,0x1C,0x08,0xB1,0xFC,0x1C,
	0x48,0xB1,0xFC,0x1C,0x88,0xB1,0xFC,0x1C,0xC8,0xB1,0xFC,0x1C,
	0x08,0xB2,0xFC,0x1C,0x48,0xB2,0xFC,0x1C,0x88,0xB2,0xFC,0x1C,
	0xC8,0xB2,0xF1,0xC0,0x8A,0x21,0xFF,0x0F,0xCF,0x70,0xA0,0x00,
	0xC8,0x1F,0x19,0x18,0x58,0x80,0xEB,0x70,0x4A,0xD9,0xCF,0x72,
	0x80,0x00,0x38,0x35,0x05,0xDB,0xB2,0x0C,0x20,0x00,0x98,0x71,
	0xD1,0xC0,0x04,0x14,0x0B,0x34,0x04,0x14,0x0A,0x34,0x04,0x14,
	0x09,0x34,0x04,0x14,0x08,0x34,0x04,0x14,0x07,0x34,0x04,0x14,
	0x06,0x34,0x04,0x14,0x05,0x34,0x04,0x14,0x04,0x34,0xC1,0xC3,
	0xC1,0xC2,0xC1,0xC1,0xC1,0xC0,0xC1,0xC4,0x45,0x2C,0x7E,0x10,
	0x0A,0x26,0x40,0x7E,0xC1,0xC4,0x6B,0x24,0x80,0x14,0xC1,0xC4,
	0x6B,0x24,0xC0,0x10,0xC1,0xC4,0x6B,0x24,0x80,0x10,0xC1,0xC4,
	0x9F,0x74,0xC1,0xC4,0x20,0x20,0x80,0x87,0xF1,0xC0,0xF2,0x0D,
	0x00,0x00,0xD6,0x0E,0xCF,0xFF,0xD1,0xC0,0xE0,0x7E,0xE0,0x78,
	0xF1,0xC0,0xCF,0x70,0x80,0x00,0x20,0x00,0x66,0x0E,0xEF,0xFF,
	0x00,0x18,0x00,0x07,0x69,0x20,0x80,0x01,0x6F,0x21,0x3F,0x00,
	0xFE,0xF1,0xE0,0x78,0x00,0xD8,0x8D,0xB8,0x21,0x07,0x20,0x00,
	0xF2,0x1A,0x18,0xB0,0xF1,0xC0,0x5A,0x0B,0x40,0x00,0x10,0xD9,
	0xCF,0x70,0xA0,0x00,0xC8,0x1F,0x12,0x18,0x58,0x80,0xD1,0xC0,
	0xE0,0x7E,0xE0,0x78,0xF1,0xC0,0x86,0x0B,0x40,0x00,0xCF,0x70,
	0x80,0x00,0x24,0x00,0x20,0x80,0x1B,0xC8,0x24,0x78,0x2F,0x28,
	0x01,0x00,0x4E,0x20,0x41,0x03,0xCF,0x70,0xA0,0x00,0x14,0x04,
	0x2A,0xA0,0xCF,0x70,0xA0,0x00,0x98,0x03,0x3B,0xA0,0x1D,0x80,
	0xD9,0x1A,0x58,0xB0,0xF6,0x1A,0x18,0xB0,0xD8,0x12,0x8D,0xB0,
	0x9C,0xE5,0x01,0xDE,0x0B,0xF2,0xEB,0x70,0x8A,0x21,0xC4,0x02,
	0xCF,0x72,0x80,0x00,0x4D,0x35,0xC9,0x73,0xBE,0x0B,0x20,0x00,
	0x98,0x75,0xB2,0x0E,0x20,0x00,0xF2,0x1A,0x98,0xB3,0x99,0x03,
	0x40,0x00,0xE0,0x78,0x06,0xD8,0xD9,0x1A,0x18,0xB0,0x01,0xD8,
	0x96,0xB8,0x99,0x06,0x20,0x00,0xF2,0x1A,0x18,0xB0,0xE0,0x78,
	0xF1,0xC0,0x0E,0x0B,0x40,0x00,0xCF,0x71,0x03,0x00,0x40,0x0D,
	0xCF,0x70,0xA0,0x00,0xA8,0x20,0x20,0xA0,0xFB,0xC9,0x04,0x20,
	0xBE,0x8F,0x5E,0x04,0x00,0x00,0x19,0xF2,0x44,0x20,0xC0,0x4B,
	0xCF,0x71,0xA0,0x00,0xD0,0x1B,0x38,0x81,0x05,0x79,0x06,0x26,
	0xC2,0x78,0x00,0x00,0x00,0x20,0x05,0x22,0x7E,0x80,0x13,0xF4
};
