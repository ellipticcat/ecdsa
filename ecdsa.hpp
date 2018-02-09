#ifndef ecdsa_hpp
#define ecdsa_hpp

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <experimental/optional>
#include <iostream>
#include <string>
#include <memory>

namespace ecdsa {
class signature
{
    ECDSA_SIG * impl;
#ifdef __ecdsa_use_der_cache
    mutable struct
    {
        char * buf;
        int size;
    } derCache;
#endif

public:
    signature(ECDSA_SIG* &sig)
    : impl{std::move(sig)}
#ifdef __ecdsa_use_der_cache
    , derCache{nullptr, 0}
#endif
    {};
    
    signature(const signature&) = delete;
    
    signature(signature&& from)
    {
        this->impl = std::move(from.impl);
        from.impl = nullptr;
#ifdef __ecdsa_use_der_cache
        this->derCache.buf = std::move(from.derCache.buf);
        this->derCache.size = from.derCache.size;
        from.derCache.buf = nullptr;
        from.derCache.size = 0;
#endif
    }

    const ECDSA_SIG * raw_ptr() const
    {
        return impl;
    }

    std::string r_hex() const
    {
        return std::string(BN_bn2hex(impl->r));
    }

    std::string s_hex() const
    {
        return std::string(BN_bn2hex(impl->s));
    }

    std::experimental::optional<std::string> der() const
    {
#ifdef __ecdsa_use_der_cache
        if (derCache.buf)
            return std::string{derCache.buf, (std::size_t)derCache.size};
#endif
        unsigned char * tbuf = nullptr;
        int dsize = i2d_ECDSA_SIG((const ECDSA_SIG*)impl, &tbuf);

        if (!dsize)
            return {};

        char * rbuf = (char*)calloc(dsize, 1);
        memmove(rbuf, tbuf, dsize);

        OPENSSL_free(tbuf);
        tbuf = nullptr;

        std::string ret = std::string{rbuf, (std::size_t)dsize};
        
#ifdef __ecdsa_use_der_cache
        derCache.buf = std::move(rbuf);
        derCache.size = dsize;
#else
        free(rbuf);
#endif
        return ret;
    }

    ssize_t write_der_to(FILE* f)
    {
        if (auto der = this->der())
            return fwrite(der->c_str(), der->length(), 1, f);
        return 0;
    }

    ~signature()
    {
        if (impl)
            ECDSA_SIG_free(impl);
        impl = nullptr;
#ifdef __ecdsa_use_der_cache
        if (derCache.buf) {
            free(derCache.buf);
            derCache.buf = nullptr;
            derCache.size = 0;
        }
#endif
    }
};
    
class context
{
    struct ec_key_st * private_key;
public:

    context(struct ec_key_st* &key __attribute__((nonnull)))
    : private_key{key}
    {};
    
    context(const context&) = delete;
    
    context(context&& from)
    {
        this->private_key = std::move(from.private_key);
        from.private_key = nullptr;
    }

    static std::unique_ptr<context> create_with_keyfile(const std::string& path)
    {
        auto evp_private_key = EVP_PKEY_new();
        auto fptr_private_key = fopen(path.c_str(), "r");

        if (!fptr_private_key) {
            EVP_PKEY_free(evp_private_key);
            return nullptr;
        }
        
        PEM_read_PrivateKey(fptr_private_key,
                            &evp_private_key,
                            nullptr,
                            nullptr);

        fclose(fptr_private_key);

        struct ec_key_st * ec_key = EVP_PKEY_get1_EC_KEY(evp_private_key);
        if (!EC_KEY_check_key(ec_key) || !ec_key) {
            if (ec_key)
                EC_KEY_free(ec_key);
            EVP_PKEY_free(evp_private_key);
            return nullptr;
        }

        return std::make_unique<context>(ec_key);
    }

    std::unique_ptr<ecdsa::signature> sign(const unsigned char * dgst,
                                           int dgst_len)
    {
        ECDSA_SIG* temp = ECDSA_do_sign(dgst, dgst_len, private_key);
        if (temp)
            return std::make_unique<ecdsa::signature>(temp);
        return nullptr;
    }
    
    bool verify(const ecdsa::signature& sig,
                const unsigned char * dgst,
                int dgst_len)
    {
        return ECDSA_do_verify(dgst, dgst_len, sig.raw_ptr(), private_key);
    }

    ~context()
    {
        if (private_key)
            EC_KEY_free(private_key);
        private_key = nullptr;
    }
};
};

#endif /* ecdsa_hpp */
