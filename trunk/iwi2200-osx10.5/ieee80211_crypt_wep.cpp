/*
 *  ;;_crypt_wep.cpp
 *  iwi2200
 *
 *  Created by Asaf Algawi on 8/21/07.
 *  Copyright 2007 __MyCompanyName__. All rights reserved.
 *
 */

#include "iwi2200.h"
#include "net/ieee80211.h"

int m_append(mbuf_t m0, int len, u8* cp)
{
	mbuf_t m,n;
	int remainder, space;
	for (m = m0; mbuf_next(m) != NULL; m=mbuf_next(m));
	remainder = len;
	space = mbuf_trailingspace(m);
	if (space > 0 )
	{
		if (space > remainder)
			space = remainder;
		bcopy(cp, ((u8*) mbuf_data(m)) + mbuf_len(m), space);
		mbuf_setlen(m,mbuf_len(m)+space);
		cp+= space, remainder -=space;
	}
	while (remainder > 0)
	{
		mbuf_get(MBUF_WAITOK, mbuf_type(m),&n);
		if (!n) break;
		mbuf_setlen(n,min(mbuf_len(m),remainder));
		bcopy(cp, ((u8*) mbuf_data(m)), mbuf_len(n));
		cp += mbuf_len(n), remainder -= mbuf_len(n);
		mbuf_setnext(m,n);
		m=n;
	}
	
	if (mbuf_flags(m0) & MBUF_PKTHDR)
		mbuf_pkthdr_setlen(m,len-remainder);
	return remainder == 0;
};

static const uint32_t crc32_table[256] = {
         0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
         0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
         0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
         0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
         0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
         0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
         0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
         0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
         0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
         0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
         0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
         0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
         0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
         0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
         0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
         0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
         0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
         0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
         0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
         0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
         0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
         0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
         0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
         0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
         0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
         0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
         0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
         0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
         0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
         0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
         0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
         0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
         0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
         0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
         0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
         0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
         0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
         0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
         0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
         0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
         0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
         0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
         0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
         0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
         0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
         0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
         0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
         0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
         0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
         0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
         0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
         0x2d02ef8dL};

struct prism2_wep_data {
	u32 iv;
#define WEP_KEY_LEN 13
	u8 key[WEP_KEY_LEN + 1];
	u8 key_len;
	u8 key_idx;
	//struct crypto_blkcipher *tx_tfm;
	//struct crypto_blkcipher *rx_tfm;
};

static int prism2_wep_encrypt(mbuf_t skb, int hdr_len, void *priv)
{
	if (!priv) return -1;
	#define S_SWAP(a,b) do { uint8_t t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
	struct prism2_wep_data *wep = (prism2_wep_data*) priv;
	mbuf_t m = skb;
	u8 rc4key[19];
	u8 icv[4];
	u32 i,j,k,crc;
	size_t buflen,data_len;
	u8 S[256];
	u8 *pos;
	u_int off, keylen;
	
	
	//mbuf_pullup(&m,hdr_len);
				   
	u8 *data = (u8*) mbuf_data(m);
	/*copy public key*/
	bcopy(data+hdr_len, rc4key, 3);
	/*copy private key*/
	bcopy(wep->key, rc4key+3,wep->key_len);
	
	IWI_DEBUG("key created\n");
	
	
	/*setup RC4 state*/
	for (i=0; i<256; i++)
	{
		S[i] = i;
	}
	j=0;
	keylen = wep->key_len+3;
	for (i=0; i<256; i++)
	{
		j = (j+S[i] + rc4key[i % keylen]) & 0xff;
		S_SWAP(i,j);
	}
	
	/*compute CRC32 over unencrypted data*/
	off=hdr_len + 4;
	data_len = mbuf_len(m) - off;
	crc = ~0;
	i=j=0;
	pos = (u8*) mbuf_data(m) + off;
	buflen = mbuf_len(m)-off;
	for (;;)
	{
		if (buflen > data_len)
				buflen =data_len;
		data_len -= buflen;
		for (k=0; k<buflen; k++)
			{
				crc = crc32_table[(crc ^ *pos) & 0xff] ^ (crc >> 8);
				i = (i+1) & 0xff;
				j = (j+S[i]) & 0xff;
				S_SWAP(i,j);
				*pos++ ^= S[(S[i] + S[j]) & 0xff];
			}
		if (mbuf_next(m)==NULL)
		{
			if (data_len!=0)
			{
				IWI_ERR("out of data for WEP encryption");
				return 0;
			}
			break;
		}
		m = mbuf_next(m);
		pos = (u8*) mbuf_data(m);
		buflen = mbuf_len(m);
	}
	crc = ~crc;
	
	// Append little endian crc32 and encrypt it to produce ICV.
	icv[0] = crc;
	icv[1] = crc >> 8;
	icv[2] = crc >> 16;
	icv[3] = crc >> 24;
	for (k=0; k<4; k++)
	{
		i= (i+1) & 0xff;
		j= (j+S[i]) & 0xff;
		S_SWAP(i,j);
		icv[k] ^= S[(S[i] + S[j]) & 0xff];
	}
	//IWI_DEBUG("calling m_append\n");
	bcopy(icv, skb_put(m,4),4);
	return 1;
	//return m_append(m, 4, icv);
	#undef S_SWAP
}





static int prism2_wep_decrypt(mbuf_t skb, int hdr_len, void* priv)
{
	if (!priv) return -1;
	#define S_SWAP(a,b) do { uint8_t t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
	struct prism2_wep_data *wep = (prism2_wep_data*) priv;
	mbuf_t m = skb;
	uint8_t rc4key[19];
	uint8_t icv[4];
	uint32_t i,j,k,crc;
	size_t buflen, data_len;
	uint8_t S[256];
	uint8_t *pos;
	u_int off,keylen;
	
	rc4key[0]=0;
	
	//mbuf_pullup(&m,hdr_len);
	
	/*copy public part of key.*/
	bcopy((uint8_t*) mbuf_data(m) + hdr_len, rc4key, 3);
	/*copy private part of key.*/
	bcopy(wep->key, rc4key+3,wep->key_len);
	
	IWI_DEBUG("public + private key: %s\n",rc4key);
	
	// setup rc4 state:
	for (i=0; i<256; i++)
		S[i] = i;
	j=0;
	keylen = wep->key_len + 3;
	for (i=0; i<256; i++)
	{
		j = (j+S[i] +rc4key[i % keylen]) & 0xff;
		S_SWAP(i,j);
	}
	
	off = hdr_len + 4;
	data_len = mbuf_len(m) - (off + 4);
	
	
	//compute crc32 over unencrypted data and apply rc4 to data
	crc = ~0;
	i = j = 0;
	pos = ((uint8_t*) mbuf_data(m)) + off;
	buflen = mbuf_len(m) - off;
	for (;;)
	{
		if (buflen > data_len)
			buflen = data_len;
		data_len -= buflen;
		for (k=0; k<buflen; k++)
		{
			i = (i+1) & 0xff;
			j = (j+S[i]) & 0xff;
			S_SWAP(i,j);
			*pos ^= S[(S[i]+S[j])& 0xff];
			crc = crc32_table[(crc^*pos) & 0xff] ^ (crc>>8);
			pos++;
		}
		m = mbuf_next(m);
		if (m==NULL)
		{
			if (data_len != 0)
			{
				IWI_ERR("missing_data");
				return 0;
			}
			break;
		}
		pos = (uint8_t*) mbuf_data(m);
		buflen = mbuf_len(m);
		
	}
	crc = ~crc;
	
	//encrypt little endian crc32 and verify it match with recieved ICV
	
	icv[0] = crc;
	icv[1] = crc>>8;
	icv[2] = crc>>16;
	icv[3] = crc>>24;
	for (k=0; k< 4; k++)
	{
		i = (i+1) & 0xff;
		j = (j+S[i]) & 0xff;
		S_SWAP(i,j);
		uint8_t pos_t=*pos++;
		if ((icv[k] ^ S[(S[i] + S[j]) & 0xff]) != pos_t) //ICV mismatch, drop frame.
		{
			IWI_ERR("key mismatch\n");
			return -2;
		}
	}
	
	return 1;
	#undef S_SWAP
}

static int prism2_wep_set_key(void *key, int len, u8 * seq, void *priv)
{
	if (!priv) return -1;
	struct prism2_wep_data *wep = (prism2_wep_data *)priv;

	if (len < 0 || len > WEP_KEY_LEN)
		return -1;

	bcopy(key, wep->key, len);
	wep->key_len = len;

	return 0;
}

static int wep_decrypt(mbuf_t skb, int hdr_len, void* priv)
{
	
	mbuf_t m = skb;
	
	if (prism2_wep_decrypt(m,hdr_len,priv)!=1) return 0;
	
//#define ovbcopy(f, t, l) bcopy((f), (t), (l))
	bcopy(mbuf_data(m),((uint8_t*) mbuf_data(m)) + 4,hdr_len);
	mbuf_adj(skb,4);
	mbuf_adj(skb,-4);
	//mbuf_setflags(skb,mbuf_flags(m) | MBUF_PKTHDR);
	
	return 1;
	
}

static int wep_encrypt(mbuf_t skb, int hdr_len, void* priv)
{
	uint32_t iv;
	uint8_t *ivp;
	int hdrlen;

	hdrlen = hdr_len;
	struct prism2_wep_data *wep = (prism2_wep_data *)priv;


	mbuf_prepend(&skb,4,MBUF_WAITOK);
	if (!skb) return 0;
	ivp = (uint8_t*)mbuf_data(skb);
	bcopy(ivp + 4, ivp, hdrlen);
	ivp += hdrlen;


	iv = wep->iv;
	if ((iv & 0xff00) == 0xff00)
	{
		int b = (iv & 0xff0000) >> 16;
		if (3<=b && b<16)
			{
				iv +=0x100;
			}
	}
	wep->iv = iv + 1;
	
#if defined(__BIG_ENDIAN__)
	// apple ppc hardware
	ivp[0] = iv >> 0;
	ivp[1] = iv >> 8;
	ivp[2] = iv >> 16;
#else
	// intel hardware
	ivp[2] = iv >> 0;
	ivp[1] = iv >> 8;
	ivp[0] = iv >> 16;
#endif
		
	ivp[3] = wep->key_idx;
	
	/* call software encrypt
		our hardware support hardware encryption but since
		i'm not so familiar with the driver code and i have this beutiful implementation of
		the BSD WEP encryption in the BSD IEEE80211 layer i will use that.
		maybe other devs can set the hardware encryption.
	*/
	IWI_DEBUG("calling encrypt\n");
	return prism2_wep_encrypt(skb,hdr_len,wep);
	//return 1;

	
	
}


static int prism2_wep_get_key(void *key, int len, u8 * seq, void *priv)
{
	if (!priv) return -1;
	struct prism2_wep_data *wep = (prism2_wep_data *)priv;

	if (len < wep->key_len)
		return -1;

	bcopy( wep->key, key, wep->key_len);

	return wep->key_len;
}

static char *prism2_wep_print_stats(char *p, void *priv)
{
	if (!priv) return NULL;
	struct prism2_wep_data *wep = (prism2_wep_data *)priv;
	p += sprintf(p, "key[%d] alg=WEP len=%d\n", wep->key_idx, wep->key_len);
	return p;
}

static void *prism2_wep_init(int keyidx)
{

	struct prism2_wep_data *priv;

	priv = (prism2_wep_data*) IOMalloc(sizeof(*priv));
	if (priv == NULL)
		goto fail;
	priv->key_idx = keyidx;
/*
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	priv->tx_tfm = crypto_alloc_blkcipher("ecb(arc4)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(priv->tx_tfm)) {
#else
	priv->tx_tfm = crypto_alloc_tfm("arc4", 0);
	if (priv->tx_tfm == NULL) {
#endif
		printk(KERN_DEBUG "ieee80211_crypt_wep: could not allocate "
		       "crypto API arc4\n");
		priv->tx_tfm = NULL;
		goto fail;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	priv->rx_tfm = crypto_alloc_blkcipher("ecb(arc4)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(priv->rx_tfm)) {
#else
	priv->rx_tfm = crypto_alloc_tfm("arc4", 0);
	if (priv->rx_tfm == NULL) {
#endif
		printk(KERN_DEBUG "ieee80211_crypt_wep: could not allocate "
		       "crypto API arc4\n");
		priv->rx_tfm = NULL;
		goto fail;
	}
	*/
	/* start WEP IV from a random value */
	read_random(&priv->iv, 4);

	return priv;

      fail:
	if (priv) {
		//if (priv->tx_tfm);
//			crypto_free_blkcipher(priv->tx_tfm);
		//if (priv->rx_tfm);
//			crypto_free_blkcipher(priv->rx_tfm);
		IOFree(priv,sizeof(*priv));
	}
	return NULL;
}

static void prism2_wep_deinit(void *priv)
{
	if (!priv) return;
	struct prism2_wep_data *_priv = (prism2_wep_data*)priv;
	if (_priv) {
		//if (_priv->tx_tfm);
	//		crypto_free_blkcipher(_priv->tx_tfm);
		//if (_priv->rx_tfm);
	//		crypto_free_blkcipher(_priv->rx_tfm);
	}
	IOFree(_priv, sizeof(*_priv));
}

/* Add WEP IV/key info to a frame that has at least 4 bytes of headroom */
static int prism2_wep_build_iv(mbuf_t skb, int hdr_len,
			       u8 *key, int keylen, void *priv)
{
	if (!priv) 
	{
		IWI_ERR("null priv");
		return -1;
	}
	struct prism2_wep_data *wep = (prism2_wep_data*) priv;
	u32 klen, len;
	u8 *pos;

	if (mbuf_leadingspace(skb) < 4 || mbuf_len(skb) < hdr_len)
		return -1;

	len = mbuf_len(skb) - hdr_len;
	pos = (u8*)skb_push(skb, 4);
	memmove(pos, pos + 4, hdr_len);
	pos += hdr_len;

	klen = 3 + wep->key_len;

	wep->iv++;

	/* Fluhrer, Mantin, and Shamir have reported weaknesses in the key
	 * scheduling algorithm of RC4. At least IVs (KeyByte + 3, 0xff, N)
	 * can be used to speedup attacks, so avoid using them. */
	if ((wep->iv & 0xff00) == 0xff00) {
		u8 B = (wep->iv >> 16) & 0xff;
		if (B >= 3 && B < klen)
			wep->iv += 0x0100;
	}

	/* Prepend 24-bit IV to RC4 key and TX frame */
	*pos++ = (wep->iv >> 16) & 0xff;
	*pos++ = (wep->iv >> 8) & 0xff;
	*pos++ = wep->iv & 0xff;
	*pos++ = wep->key_idx << 6;

	return 0;
}


static struct list_head list;
static struct ieee80211_crypto_ops ieee80211_crypt_wep = {
	"WEP",
	list,
	prism2_wep_init,
	prism2_wep_deinit,
	prism2_wep_build_iv,
	wep_encrypt,
	wep_decrypt,
	NULL,
	NULL,
	prism2_wep_set_key,
	prism2_wep_get_key,
	prism2_wep_print_stats,
	NULL,
	NULL,
	4,
	4};

void darwin_iwi2200::free_wep(ieee80211_crypt_data *tmp)
{
	if (tmp)
	{
		 tmp->ops=NULL;
		 IOFree(tmp->priv,sizeof(prism2_wep_data));
		 tmp->priv=NULL;
		 IOFree(tmp,sizeof(ieee80211_crypt_data));
		 tmp=NULL;
	}
}
	
ieee80211_crypt_data* darwin_iwi2200::init_wep(void *key, int len, int idx)
{
	ieee80211_crypt_data* tmp = (ieee80211_crypt_data*) IOMalloc(sizeof(ieee80211_crypt_data)+sizeof(struct prism2_wep_data));
	tmp->ops=&ieee80211_crypt_wep;
	tmp->priv=tmp->ops->init(idx);
	prism2_wep_set_key(key,  len, NULL, tmp->priv);

	/*int i=0;
	IWI_LOG("key password [");
	while( i< ((prism2_wep_data*)(tmp->priv))->key_len)
	{
		IOLog("%x",((prism2_wep_data*)(tmp->priv))->key[i++]);
		if (i<((prism2_wep_data*)(tmp->priv))->key_len) IOLog(":");
	}
	IOLog("] ");
	i=0;
	while( i< ((prism2_wep_data*)(tmp->priv))->key_len)
	{
		IOLog("%c",((prism2_wep_data*)(tmp->priv))->key[i++]);
	}
	IOLog(" size %d\n",((prism2_wep_data*)(tmp->priv))->key_len);*/
	return tmp;
}


