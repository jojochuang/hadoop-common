package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;

import java.io.Serializable;

public class SerializableEncryptedKeyVersion implements Serializable {

  public String encryptionKeyName;
  public String encryptionKeyVersionName;
  public byte[] encryptedKeyIv;
  public byte[] material;

  public SerializableEncryptedKeyVersion(KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion) {
    this.encryptionKeyName = encryptedKeyVersion.getEncryptionKeyName();
    this.encryptionKeyVersionName = encryptedKeyVersion.getEncryptionKeyVersionName();
    this.encryptedKeyIv = encryptedKeyVersion.getEncryptedKeyIv();
    this.material = encryptedKeyVersion.getEncryptedKeyVersion().getMaterial();
  }

  public String getEncryptionKeyName() {
    return encryptionKeyName;
  }

}
