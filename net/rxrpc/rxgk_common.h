/* SPDX-License-Identifier: GPL-2.0-or-later */
/* rxgk common bits
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <crypto/krb5.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>

/*
 * Per-key number context.  This is replaced when the connection is rekeyed.
 */
struct rxgk_context {
	refcount_t		usage;
	unsigned int		key_number;	/* Rekeying number (goes in the rx header) */
	unsigned long		flags;
#define RXGK_TK_NEEDS_REKEY	0		/* Set if this needs rekeying */
	unsigned long		expiry;		/* Expiration time of this key */
	long long		bytes_remaining; /* Remaining Tx lifetime of this key */
	const struct krb5_enctype *krb5;	/* RxGK encryption type */
	const struct rxgk_key	*key;

	/* We need up to 7 keys derived from the transport key, but we don't
	 * actually need the transport key.  Each key is derived by
	 * DK(TK,constant).
	 */
	struct krb5_enc_keys	tx_enc;		/* Transmission key */
	struct krb5_enc_keys	rx_enc;		/* Reception key */
	struct crypto_shash	*tx_Kc;		/* Transmission checksum key */
	struct crypto_shash	*rx_Kc;		/* Reception checksum key */
	struct krb5_enc_keys	resp_enc;	/* Response packet enc key */
};

#define xdr_round_up(x) (round_up((x), sizeof(__be32)))

/*
 * rxgk_app.c
 */
int rxgk_yfs_decode_ticket(struct sk_buff *, unsigned int, unsigned int,
			   u32 *, struct key **);
int rxgk_extract_token(struct rxrpc_connection *,
		       struct sk_buff *, unsigned int, unsigned int,
		       struct key **, u32 *, const char **);

/*
 * rxgk_kdf.c
 */
struct rxgk_context *rxgk_generate_transport_key(struct rxrpc_connection *,
						 const struct rxgk_key *, unsigned int, gfp_t);
int rxgk_set_up_token_cipher(const struct krb5_buffer *, struct krb5_enc_keys *,
			     unsigned int, const struct krb5_enctype **,
			     gfp_t);
void rxgk_put(struct rxgk_context *);

/*
 * Apply encryption and checksumming functions to part of an skbuff.
 */
static inline
int rxgk_encrypt_skb(const struct krb5_enctype *krb5,
		     struct krb5_enc_keys *keys,
		     struct sk_buff *skb,
		     u16 secure_offset, u16 secure_len,
		     u16 data_offset, u16 data_len,
		     bool preconfounded)
{
	struct scatterlist sg[16];
	int nr_sg;

	sg_init_table(sg, ARRAY_SIZE(sg));
	nr_sg = skb_to_sgvec(skb, sg, secure_offset, secure_len);
	if (unlikely(nr_sg < 0))
		return nr_sg;

	data_offset -= secure_offset;
	return crypto_krb5_encrypt(krb5, keys, sg, nr_sg, secure_len,
				   data_offset, data_len, preconfounded);
}

/*
 * Apply decryption and checksumming functions to part of an skbuff.  The
 * offset and length are updated to reflect the actual content of the encrypted
 * region.
 */
static inline
int rxgk_decrypt_skb(const struct krb5_enctype *krb5,
		     struct krb5_enc_keys *keys,
		     struct sk_buff *skb,
		     unsigned int *_offset, unsigned int *_len,
		     int *_error_code)
{
	struct scatterlist sg[16];
	size_t offset = 0, len = *_len;
	int nr_sg, ret;

	sg_init_table(sg, ARRAY_SIZE(sg));
	nr_sg = skb_to_sgvec(skb, sg, *_offset, len);
	if (unlikely(nr_sg < 0))
		return nr_sg;

	ret = crypto_krb5_decrypt(krb5, keys, sg, nr_sg,
				  &offset, &len, _error_code);

	*_offset += offset;
	*_len = len;
	return ret;
}

/*
 * Generate a checksum over some metadata and part of an skbuff and insert the
 * MIC into the skbuff immediately prior to the data.
 */
static inline
int rxgk_get_mic_skb(const struct krb5_enctype *krb5,
		     struct crypto_shash *shash,
		     const struct krb5_buffer *metadata,
		     struct sk_buff *skb,
		     u16 secure_offset, u16 secure_len,
		     u16 data_offset, u16 data_len)
{
	struct scatterlist sg[16];
	int nr_sg;

	sg_init_table(sg, ARRAY_SIZE(sg));
	nr_sg = skb_to_sgvec(skb, sg, secure_offset, secure_len);
	if (unlikely(nr_sg < 0))
		return nr_sg;

	data_offset -= secure_offset;
	return crypto_krb5_get_mic(krb5, shash, metadata, sg, nr_sg, secure_len,
				   data_offset, data_len);
}

/*
 * Check the MIC on a region of an skbuff.  The offset and length are updated
 * to reflect the actual content of the secure region.
 */
static inline
int rxgk_verify_mic_skb(const struct krb5_enctype *krb5,
			struct crypto_shash *shash,
			const struct krb5_buffer *metadata,
			struct sk_buff *skb,
			unsigned int *_offset, unsigned int *_len,
			u32 *_error_code)
{
	struct scatterlist sg[16];
	size_t offset = 0, len = *_len;
	int nr_sg, ret;

	sg_init_table(sg, ARRAY_SIZE(sg));
	nr_sg = skb_to_sgvec(skb, sg, *_offset, len);
	if (unlikely(nr_sg < 0))
		return nr_sg;

	ret = crypto_krb5_verify_mic(krb5, shash, metadata, sg, nr_sg,
				     &offset, &len, _error_code);

	*_offset += offset;
	*_len = len;
	return ret;
}
