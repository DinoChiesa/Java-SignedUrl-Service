// Copyright 2019-2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.examples;

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

public class KeyUtility {
  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  private KeyUtility() throws Exception {}

  protected static KeyPair produceKeyPair(PrivateKey privateKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    RSAPrivateCrtKey privCrtKey = (RSAPrivateCrtKey) privateKey;
    PublicKey publicKey =
        KeyFactory.getInstance("RSA")
            .generatePublic(
                new RSAPublicKeySpec(
                    ((RSAPrivateKey) privateKey).getPrivateExponent(),
                    privCrtKey.getPublicExponent()));
    return new KeyPair(publicKey, privateKey);
  }

  public static KeyPair readKeyPair(String privateKeyPemString, String password) throws Exception {
    if (password == null) password = "";

    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
    PEMParser pr = new PEMParser(new StringReader(privateKeyPemString));
    Object o = pr.readObject();

    if (o instanceof PrivateKeyInfo) {
      // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
      PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo) o);
      return produceKeyPair(privateKey);
    }

    if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
      // produced by "openssl genpkey" or the series of commands reqd to sign an ec key
      PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) o;
      JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
          new JceOpenSSLPKCS8DecryptorProviderBuilder();
      InputDecryptorProvider decryptorProvider =
          decryptorProviderBuilder.build(password.toCharArray());
      PrivateKeyInfo privateKeyInfo =
          pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
      PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
      return produceKeyPair(privateKey);
    }

    if (o instanceof PEMEncryptedKeyPair) {
      PEMDecryptorProvider decProv =
          new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
      return converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
    }

    if (o instanceof PEMEncryptedKeyPair) {
      // produced by "openssl genrsa" or "openssl ec -genkey"
      PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) o;
      PEMDecryptorProvider decryptorProvider =
          new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
      return converter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptorProvider));
    }

    if (o instanceof PEMKeyPair) {
      // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
      return converter.getKeyPair((PEMKeyPair) o);
    }

    throw new Exception("unknown object type when decoding private key");
  }
}
