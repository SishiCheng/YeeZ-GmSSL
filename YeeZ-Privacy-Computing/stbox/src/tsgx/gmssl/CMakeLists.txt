add_definitions(-DUSE_NUM_NONE -DUSE_FIELD_5X52 -DHAVE___INT128 -DUSE_FIELD_INV_BUILTIN -DUSE_SCALAR_4X64 -DUSE_SCALAR_INV_BUILTIN -DUSE_LOW_HEAP)

include_directories(${PROJECT_SOURCE_DIR}/stbox/include/stbox/tsgx)

add_library(
	gmssl
	SHARED
	aes.c
	aes_modes.c
	asn1.c
	base64.c
	block_cipher.c
	chacha20.c
	cms.c
	debug.c
	des.c
	digest.c
	ec.c
	gcm.c
	gf128.c
	hash_drbg.c
	hex.c
	hkdf.c
	hmac.c
	md5.c
	pbkdf2.c
	pem.c
	pkcs8.c
	rand.c
	rc4.c
#	src/rdrand.c
	rsa.c
	sha1.c
	sha256.c
	sha512.c
	sm2_alg.c
	sm2_key.c
	sm2_lib.c
	sm3.c
	sm3_hmac.c
	sm3_kdf.c
	sm4_common.c
	sm4_enc.c
	sm4_modes.c
	sm4_setkey.c
	sm9_alg.c
	sm9_key.c
	sm9_lib.c
	tlcp.c
	tls.c
	tls12.c
	tls13.c
	tls_trace.c
	version.c
	x509_alg.c
	x509_cer.c
	x509_crl.c
	x509_ext.c
	x509_oid.c
	x509_req.c
	x509_str.c
	zuc.c
	zuc_modes.c
	sdf/sdf.c
	sdf/sdf_lib.c
	sdf/sdf_meth.c
	sdf/sdf_ext.c
	sdf/sdf_sansec.c
	skf/skf.c
	skf/skf_lib.c
	skf/skf_meth.c
	skf/skf_ext.c
	skf/skf_prn.c
	skf/skf_wisec.c
)
target_link_libraries(gmssl dl)

