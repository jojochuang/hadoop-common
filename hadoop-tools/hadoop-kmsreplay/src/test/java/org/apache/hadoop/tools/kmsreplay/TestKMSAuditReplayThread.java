package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.mapreduce.Mapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.concurrent.DelayQueue;

import static org.mockito.Matchers.any;
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
    when(context.getConfiguration()).thenReturn(new Configuration());

    KMSAuditReplayThread thread = new KMSAuditReplayThread(context, commandQueue, keyProviderCache);
    AuditReplayCommand command = new AuditReplayCommand(0, "DECRYPT_EEK", "key1", "foo", 1, 0);

    KeyProviderCryptoExtension kpce = mock(KeyProviderCryptoExtension.class);
    when(keyProviderCache.get(any())).thenReturn(kpce);
    thread.replayLog(command);
    verify(kpce, times(1)).decryptEncryptedKey(any());
  }

  @Test
  public void replayGenerateEEK() throws IOException, GeneralSecurityException {
    Mapper.Context context = mock(Mapper.Context.class);
    when(context.getConfiguration()).thenReturn(new Configuration());

    KMSAuditReplayThread thread = new KMSAuditReplayThread(context, commandQueue, keyProviderCache);
    AuditReplayCommand command = new AuditReplayCommand(0, "GENERATE_EEK", "key1", "foo", 1, 0);

    KeyProviderCryptoExtension kpce = mock(KeyProviderCryptoExtension.class);
    when(keyProviderCache.get(any())).thenReturn(kpce);
    thread.replayLog(command);
    verify(kpce, times(1)).generateEncryptedKey(any());
  }
}