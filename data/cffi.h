uint32_t random32(void);
void random_buffer(uint8_t *buf, size_t len);
uint32_t random_uniform(uint32_t n);
void random_permute(char *buf, size_t len);
int random_init(void);
typedef struct _SHA1_CTX
{
  uint32_t state[5];
  uint64_t bitcount;
  uint32_t buffer[16];
} SHA1_CTX;
typedef struct _SHA256_CTX
{
  uint32_t state[8];
  uint64_t bitcount;
  uint32_t buffer[16];
} SHA256_CTX;
typedef struct _SHA512_CTX
{
  uint64_t state[8];
  uint64_t bitcount[2];
  uint64_t buffer[16];
} SHA512_CTX;
extern const uint32_t sha256_initial_hash_value[8];
extern const uint64_t sha512_initial_hash_value[8];
void sha1_Transform(const uint32_t *state_in, const uint32_t *data, uint32_t *state_out);
void sha1_Init(SHA1_CTX *);
void sha1_Update(SHA1_CTX *, const uint8_t *, size_t);
void sha1_Final(SHA1_CTX *, uint8_t [20]);
char *sha1_End(SHA1_CTX *, char [41]);
void sha1_Raw(const uint8_t *, size_t, uint8_t [20]);
char *sha1_Data(const uint8_t *, size_t, char [41]);
void sha256_Transform(const uint32_t *state_in, const uint32_t *data, uint32_t *state_out);
void sha256_Init(SHA256_CTX *);
void sha256_Update(SHA256_CTX *, const uint8_t *, size_t);
void sha256_Final(SHA256_CTX *, uint8_t [32]);
char *sha256_End(SHA256_CTX *, char [65]);
void sha256_Raw(const uint8_t *, size_t, uint8_t [32]);
char *sha256_Data(const uint8_t *, size_t, char [65]);
void sha512_Transform(const uint64_t *state_in, const uint64_t *data, uint64_t *state_out);
void sha512_Init(SHA512_CTX *);
void sha512_Update(SHA512_CTX *, const uint8_t *, size_t);
void sha512_Final(SHA512_CTX *, uint8_t [64]);
char *sha512_End(SHA512_CTX *, char [129]);
void sha512_Raw(const uint8_t *, size_t, uint8_t [64]);
char *sha512_Data(const uint8_t *, size_t, char [129]);
typedef struct SHA3_CTX
{
  uint64_t hash[25];
  uint64_t message[24];
  unsigned rest;
  unsigned block_size;
} SHA3_CTX;
void sha3_224_Init(SHA3_CTX *ctx);
void sha3_256_Init(SHA3_CTX *ctx);
void sha3_384_Init(SHA3_CTX *ctx);
void sha3_512_Init(SHA3_CTX *ctx);
void sha3_Update(SHA3_CTX *ctx, const unsigned char *msg, size_t size);
void sha3_Final(SHA3_CTX *ctx, unsigned char *result);
void keccak_Final(SHA3_CTX *ctx, unsigned char *result);
void keccak_256(const unsigned char *data, size_t len, unsigned char *digest);
void keccak_512(const unsigned char *data, size_t len, unsigned char *digest);
void sha3_256(const unsigned char *data, size_t len, unsigned char *digest);
void sha3_512(const unsigned char *data, size_t len, unsigned char *digest);
typedef struct 
{
  uint32_t h[8];
  uint32_t s[4];
  uint32_t t[2];
  size_t buflen;
  uint8_t nullt;
  uint8_t buf[64];
} BLAKE256_CTX;
void blake256_Init(BLAKE256_CTX *);
void blake256_Update(BLAKE256_CTX *, const uint8_t *, size_t);
void blake256_Final(BLAKE256_CTX *, uint8_t *);
void blake256(const uint8_t *, size_t, uint8_t *);
typedef struct 
{
  unsigned char buf[128];
  size_t ptr;
  union 
  {
    uint64_t wide[16];
    uint32_t narrow[32];
  } state;
  uint64_t count;
} sph_groestl_big_context;
typedef sph_groestl_big_context GROESTL512_CTX;
void groestl512_Init(void *cc);
void groestl512_Update(void *cc, const void *data, size_t len);
void groestl512_Final(void *cc, void *dst);
void groestl512_DoubleTrunc(void *cc, void *dst);
typedef enum {HASHER_SHA2, HASHER_BLAKE, HASHER_SHA2D, HASHER_BLAKED, HASHER_GROESTLD_TRUNC, HASHER_SHA3, HASHER_SHA3K} HasherType;
typedef struct 
{
  HasherType type;
  union 
  {
    SHA256_CTX sha2;
    SHA3_CTX sha3;
    BLAKE256_CTX blake;
    GROESTL512_CTX groestl;
  } ctx;
} Hasher;
void hasher_Init(Hasher *hasher, HasherType type);
void hasher_Reset(Hasher *hasher);
void hasher_Update(Hasher *hasher, const uint8_t *data, size_t length);
void hasher_Final(Hasher *hasher, uint8_t hash[32]);
void hasher_Raw(HasherType type, const uint8_t *data, size_t length, uint8_t hash[32]);
typedef struct _HMAC_SHA256_CTX
{
  uint8_t o_key_pad[64];
  SHA256_CTX ctx;
} HMAC_SHA256_CTX;
typedef struct _HMAC_SHA512_CTX
{
  uint8_t o_key_pad[128];
  SHA512_CTX ctx;
} HMAC_SHA512_CTX;
void hmac_sha256_Init(HMAC_SHA256_CTX *hctx, const uint8_t *key, const uint32_t keylen);
void hmac_sha256_Update(HMAC_SHA256_CTX *hctx, const uint8_t *msg, const uint32_t msglen);
void hmac_sha256_Final(HMAC_SHA256_CTX *hctx, uint8_t *hmac);
void hmac_sha256(const uint8_t *key, const uint32_t keylen, const uint8_t *msg, const uint32_t msglen, uint8_t *hmac);
void hmac_sha256_prepare(const uint8_t *key, const uint32_t keylen, uint32_t *opad_digest, uint32_t *ipad_digest);
void hmac_sha512_Init(HMAC_SHA512_CTX *hctx, const uint8_t *key, const uint32_t keylen);
void hmac_sha512_Update(HMAC_SHA512_CTX *hctx, const uint8_t *msg, const uint32_t msglen);
void hmac_sha512_Final(HMAC_SHA512_CTX *hctx, uint8_t *hmac);
void hmac_sha512(const uint8_t *key, const uint32_t keylen, const uint8_t *msg, const uint32_t msglen, uint8_t *hmac);
void hmac_sha512_prepare(const uint8_t *key, const uint32_t keylen, uint64_t *opad_digest, uint64_t *ipad_digest);
typedef struct _PBKDF2_HMAC_SHA256_CTX
{
  uint32_t odig[8];
  uint32_t idig[8];
  uint32_t f[8];
  uint32_t g[16];
  char first;
} PBKDF2_HMAC_SHA256_CTX;
typedef struct _PBKDF2_HMAC_SHA512_CTX
{
  uint64_t odig[8];
  uint64_t idig[8];
  uint64_t f[8];
  uint64_t g[16];
  char first;
} PBKDF2_HMAC_SHA512_CTX;
void pbkdf2_hmac_sha256_Init(PBKDF2_HMAC_SHA256_CTX *pctx, const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen);
void pbkdf2_hmac_sha256_Update(PBKDF2_HMAC_SHA256_CTX *pctx, uint32_t iterations);
void pbkdf2_hmac_sha256_Final(PBKDF2_HMAC_SHA256_CTX *pctx, uint8_t *key);
void pbkdf2_hmac_sha256(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key);
void pbkdf2_hmac_sha512_Init(PBKDF2_HMAC_SHA512_CTX *pctx, const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen);
void pbkdf2_hmac_sha512_Update(PBKDF2_HMAC_SHA512_CTX *pctx, uint32_t iterations);
void pbkdf2_hmac_sha512_Final(PBKDF2_HMAC_SHA512_CTX *pctx, uint8_t *key);
void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key);
typedef struct 
{
  uint32_t val[9];
} bignum256;
uint32_t read_be(const uint8_t *data);
void write_be(uint8_t *data, uint32_t x);
uint32_t read_le(const uint8_t *data);
void write_le(uint8_t *data, uint32_t x);
void bn_read_be(const uint8_t *in_number, bignum256 *out_number);
void bn_write_be(const bignum256 *in_number, uint8_t *out_number);
void bn_read_le(const uint8_t *in_number, bignum256 *out_number);
void bn_write_le(const bignum256 *in_number, uint8_t *out_number);
void bn_read_uint32(uint32_t in_number, bignum256 *out_number);
void bn_read_uint64(uint64_t in_number, bignum256 *out_number);
int bn_bitcount(const bignum256 *a);
unsigned int bn_digitcount(const bignum256 *a);
void bn_zero(bignum256 *a);
int bn_is_zero(const bignum256 *a);
void bn_one(bignum256 *a);
int bn_is_less(const bignum256 *a, const bignum256 *b);
int bn_is_equal(const bignum256 *a, const bignum256 *b);
void bn_cmov(bignum256 *res, int cond, const bignum256 *truecase, const bignum256 *falsecase);
void bn_lshift(bignum256 *a);
void bn_rshift(bignum256 *a);
void bn_setbit(bignum256 *a, uint8_t bit);
void bn_clearbit(bignum256 *a, uint8_t bit);
uint32_t bn_testbit(bignum256 *a, uint8_t bit);
void bn_xor(bignum256 *a, const bignum256 *b, const bignum256 *c);
void bn_mult_half(bignum256 *x, const bignum256 *prime);
void bn_mult_k(bignum256 *x, uint8_t k, const bignum256 *prime);
void bn_mod(bignum256 *x, const bignum256 *prime);
void bn_multiply(const bignum256 *k, bignum256 *x, const bignum256 *prime);
void bn_fast_mod(bignum256 *x, const bignum256 *prime);
void bn_sqrt(bignum256 *x, const bignum256 *prime);
void bn_inverse(bignum256 *x, const bignum256 *prime);
void bn_normalize(bignum256 *a);
void bn_add(bignum256 *a, const bignum256 *b);
void bn_addmod(bignum256 *a, const bignum256 *b, const bignum256 *prime);
void bn_addi(bignum256 *a, uint32_t b);
void bn_subi(bignum256 *a, uint32_t b, const bignum256 *prime);
void bn_subtractmod(const bignum256 *a, const bignum256 *b, bignum256 *res, const bignum256 *prime);
void bn_subtract(const bignum256 *a, const bignum256 *b, bignum256 *res);
void bn_divmod58(bignum256 *a, uint32_t *r);
void bn_divmod1000(bignum256 *a, uint32_t *r);
size_t bn_format(const bignum256 *amnt, const char *prefix, const char *suffix, unsigned int decimals, int exponent, bool trailing, char *out, size_t outlen);
extern const char *BASE32_ALPHABET_RFC4648;
char *base32_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen, const char *alphabet);
void base32_encode_unsafe(const uint8_t *in, size_t inlen, uint8_t *out);
uint8_t *base32_decode(const char *in, size_t inlen, uint8_t *out, size_t outlen, const char *alphabet);
bool base32_decode_unsafe(const uint8_t *in, size_t inlen, uint8_t *out, const char *alphabet);
size_t base32_encoded_length(size_t inlen);
size_t base32_decoded_length(size_t inlen);
int base58_encode_check(const uint8_t *data, int len, HasherType hasher_type, char *str, int strsize);
int base58_decode_check(const char *str, HasherType hasher_type, uint8_t *data, int datalen);
bool b58tobin(void *bin, size_t *binszp, const char *b58);
int b58check(const void *bin, size_t binsz, HasherType hasher_type, const char *base58str);
bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
int xmr_base58_addr_encode_check(uint64_t tag, const uint8_t *data, size_t binsz, char *b58, size_t b58sz);
int xmr_base58_addr_decode_check(const char *addr, size_t sz, uint64_t *tag, void *data, size_t datalen);
bool xmr_base58_encode(char *b58, size_t *b58sz, const void *data, size_t binsz);
bool xmr_base58_decode(const char *b58, size_t b58sz, void *data, size_t *binsz);
typedef uint32_t bignum25519[10];
void curve25519_copy(bignum25519 out, const bignum25519 in);
void curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b);
void curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b);
void curve25519_add_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b);
void curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b);
void curve25519_scalar_product(bignum25519 out, const bignum25519 in, const uint32_t scalar);
void curve25519_sub_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b);
void curve25519_sub_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b);
void curve25519_neg(bignum25519 out, const bignum25519 a);
void curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b);
void curve25519_square(bignum25519 out, const bignum25519 in);
void curve25519_square_times(bignum25519 out, const bignum25519 in, int count);
void curve25519_expand(bignum25519 out, const unsigned char in[32]);
void curve25519_contract(unsigned char out[32], const bignum25519 in);
void curve25519_swap_conditional(bignum25519 a, bignum25519 b, uint32_t iswap);
void curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b);
void curve25519_recip(bignum25519 out, const bignum25519 z);
void curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z);
typedef uint32_t bignum256modm_element_t;
typedef bignum256modm_element_t bignum256modm[9];
void reduce256_modm(bignum256modm r);
void barrett_reduce256_modm(bignum256modm r, const bignum256modm q1, const bignum256modm r1);
void add256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y);
void neg256_modm(bignum256modm r, const bignum256modm x);
void sub256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y);
void mul256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y);
void expand256_modm(bignum256modm out, const unsigned char *in, size_t len);
void expand_raw256_modm(bignum256modm out, const unsigned char in[32]);
void contract256_modm(unsigned char out[32], const bignum256modm in);
void contract256_window4_modm(signed char r[64], const bignum256modm in);
void contract256_slidingwindow_modm(signed char r[256], const bignum256modm s, int windowsize);
typedef unsigned char hash_512bits[64];
typedef struct ge25519_t
{
  bignum25519 x;
  bignum25519 y;
  bignum25519 z;
  bignum25519 t;
} ge25519;
typedef struct ge25519_p1p1_t
{
  bignum25519 x;
  bignum25519 y;
  bignum25519 z;
  bignum25519 t;
} ge25519_p1p1;
typedef struct ge25519_niels_t
{
  bignum25519 ysubx;
  bignum25519 xaddy;
  bignum25519 t2d;
} ge25519_niels;
typedef struct ge25519_pniels_t
{
  bignum25519 ysubx;
  bignum25519 xaddy;
  bignum25519 z;
  bignum25519 t2d;
} ge25519_pniels;
extern const uint8_t ge25519_niels_base_multiples[256][96];
extern const ge25519 ge25519_basepoint;
extern const bignum25519 ge25519_ecd;
extern const bignum25519 ge25519_ec2d;
extern const bignum25519 ge25519_sqrtneg1;
extern const ge25519_niels ge25519_niels_sliding_multiples[32];
int ed25519_verify(const unsigned char *x, const unsigned char *y, size_t len);
void ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p);
void ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p);
void ge25519_full_to_pniels(ge25519_pniels *p, const ge25519 *r);
void ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p);
void ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q, unsigned char signbit);
void ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q, unsigned char signbit);
void ge25519_double_partial(ge25519 *r, const ge25519 *p);
void ge25519_double(ge25519 *r, const ge25519 *p);
void ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q);
void ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q);
void ge25519_pack(unsigned char r[32], const ge25519 *p);
int ge25519_unpack_negative_vartime(ge25519 *r, const unsigned char p[32]);
void ge25519_set_neutral(ge25519 *r);
void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2);
void ge25519_double_scalarmult_vartime2(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const ge25519 *p2, const bignum256modm s2);
void ge25519_scalarmult(ge25519 *r, const ge25519 *p1, const bignum256modm s1);
void set256_modm(bignum256modm r, uint64_t v);
int get256_modm(uint64_t *v, const bignum256modm r);
int eq256_modm(const bignum256modm x, const bignum256modm y);
int cmp256_modm(const bignum256modm x, const bignum256modm y);
int iszero256_modm(const bignum256modm x);
void copy256_modm(bignum256modm r, const bignum256modm x);
int check256_modm(const bignum256modm x);
void mulsub256_modm(bignum256modm r, const bignum256modm a, const bignum256modm b, const bignum256modm c);
void muladd256_modm(bignum256modm r, const bignum256modm a, const bignum256modm b, const bignum256modm c);
void curve25519_set(bignum25519 r, uint32_t x);
void curve25519_set_d(bignum25519 r);
void curve25519_set_2d(bignum25519 r);
void curve25519_set_sqrtneg1(bignum25519 r);
int curve25519_isnegative(const bignum25519 f);
int curve25519_isnonzero(const bignum25519 f);
void curve25519_reduce(bignum25519 r, const bignum25519 in);
void curve25519_expand_reduce(bignum25519 out, const unsigned char in[32]);
int ge25519_check(const ge25519 *r);
int ge25519_fromfe_check(const ge25519 *r);
int ge25519_eq(const ge25519 *a, const ge25519 *b);
void ge25519_copy(ge25519 *dst, const ge25519 *src);
void ge25519_set_base(ge25519 *r);
void ge25519_mul8(ge25519 *r, const ge25519 *t);
void ge25519_neg_partial(ge25519 *r);
void ge25519_neg_full(ge25519 *r);
void ge25519_reduce(ge25519 *r, const ge25519 *t);
void ge25519_norm(ge25519 *r, const ge25519 *t);
void ge25519_add(ge25519 *r, const ge25519 *a, const ge25519 *b, unsigned char signbit);
void ge25519_fromfe_frombytes_vartime(ge25519 *r, const unsigned char *s);
int ge25519_unpack_vartime(ge25519 *r, const unsigned char *s);
void ge25519_scalarmult_base_wrapper(ge25519 *r, const bignum256modm s);
void ge25519_scalarmult_wrapper(ge25519 *r, const ge25519 *P, const bignum256modm a);
int xmr_size_varint(uint64_t num);
int xmr_write_varint(uint8_t *buff, size_t buff_size, uint64_t num);
int xmr_read_varint(uint8_t *buff, size_t buff_size, uint64_t *val);
extern const ge25519 xmr_h;
typedef unsigned char xmr_key_t[32];
typedef struct xmr_ctkey
{
  xmr_key_t dest;
  xmr_key_t mask;
} xmr_ctkey_t;
void ge25519_set_xmr_h(ge25519 *r);
void xmr_random_scalar(bignum256modm m);
void xmr_fast_hash(uint8_t *hash, const void *data, size_t length);
void xmr_hasher_init(Hasher *hasher);
void xmr_hasher_update(Hasher *hasher, const void *data, size_t length);
void xmr_hasher_final(Hasher *hasher, uint8_t *hash);
void xmr_hasher_copy(Hasher *dst, const Hasher *src);
void xmr_hash_to_scalar(bignum256modm r, const void *data, size_t length);
void xmr_hash_to_ec(ge25519 *P, const void *data, size_t length);
void xmr_derivation_to_scalar(bignum256modm s, const ge25519 *p, uint32_t output_index);
void xmr_generate_key_derivation(ge25519 *r, const ge25519 *A, const bignum256modm b);
void xmr_derive_private_key(bignum256modm s, const ge25519 *deriv, uint32_t idx, const bignum256modm base);
void xmr_derive_public_key(ge25519 *r, const ge25519 *deriv, uint32_t idx, const ge25519 *base);
void xmr_add_keys2(ge25519 *r, const bignum256modm a, const bignum256modm b, const ge25519 *B);
void xmr_add_keys2_vartime(ge25519 *r, const bignum256modm a, const bignum256modm b, const ge25519 *B);
void xmr_add_keys3(ge25519 *r, const bignum256modm a, const ge25519 *A, const bignum256modm b, const ge25519 *B);
void xmr_add_keys3_vartime(ge25519 *r, const bignum256modm a, const ge25519 *A, const bignum256modm b, const ge25519 *B);
void xmr_get_subaddress_secret_key(bignum256modm r, uint32_t major, uint32_t minor, const bignum256modm m);
void xmr_gen_c(ge25519 *r, const bignum256modm a, uint64_t amount);
