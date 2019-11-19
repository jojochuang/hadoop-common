package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.mapreduce.Mapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TestKMSAuditReplayThread {

  @Mock
  DelayQueue<AuditReplayCommand> commandQueue;

  @Mock
  Map<String, KeyProviderCryptoExtension> keyProviderCache;

  @Test
  public void replayDecryptEEK() throws IOException, GeneralSecurityException {
    Mapper.Context context = mock(Mapper.Context.class);
    Configuration conf = new Configuration();
    when(context.getConfiguration()).thenReturn(conf);

    Map<String, KeyProviderCryptoExtension.EncryptedKeyVersion> cachedKeyVersion =
        new ConcurrentHashMap<>();
    AtomicInteger totalAuditCounter = new AtomicInteger();
    AtomicInteger auditReplayCounter = new AtomicInteger();
    KMSAuditReplayThread thread = new KMSAuditReplayThread(context, commandQueue, keyProviderCache,
        cachedKeyVersion, totalAuditCounter, auditReplayCounter, false);
    AuditReplayCommand command = new AuditReplayCommand(0, "DECRYPT_EEK", "key1", "foo", 1, 0);

    KeyProviderCryptoExtension kpce = mock(KeyProviderCryptoExtension.class);
    when(keyProviderCache.get(any())).thenReturn(kpce);
    //when(kpce.getConf()).thenReturn(conf);

    KeyProvider.KeyVersion keyVersion = mock(KeyProvider.KeyVersion.class);
    when(kpce.decryptEncryptedKey(any())).thenReturn(keyVersion);

    KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion =
        mock(KeyProviderCryptoExtension.EncryptedKeyVersion.class);
    thread.addCachedKeyVersionForTest("key1", encryptedKeyVersion);

    thread.replayLog(command);
    verify(kpce, times(1)).decryptEncryptedKey(any());
  }

  @Test
  public void replayGenerateEEK() throws IOException, GeneralSecurityException {
    Mapper.Context context = mock(Mapper.Context.class);
    when(context.getConfiguration()).thenReturn(new Configuration());

    Map<String, KeyProviderCryptoExtension.EncryptedKeyVersion> cachedKeyVersion =
        new ConcurrentHashMap<>();
    AtomicInteger totalAuditCounter = new AtomicInteger();
    AtomicInteger auditReplayCounter = new AtomicInteger();
    KMSAuditReplayThread thread =
        new KMSAuditReplayThread(context, commandQueue, keyProviderCache, cachedKeyVersion,
            totalAuditCounter, auditReplayCounter, true);
    AuditReplayCommand command = new AuditReplayCommand(0, "GENERATE_EEK", "key1", "foo", 1, 0);

    KeyProviderCryptoExtension kpce = mock(KeyProviderCryptoExtension.class);
    when(keyProviderCache.get(any())).thenReturn(kpce);

    KeyProviderCryptoExtension.EncryptedKeyVersion eKV = mock(KeyProviderCryptoExtension.EncryptedKeyVersion.class);
    when(kpce.generateEncryptedKey(anyString())).thenReturn(eKV);
    thread.replayLog(command);
    verify(kpce, times(1)).generateEncryptedKey(any());
  }
}