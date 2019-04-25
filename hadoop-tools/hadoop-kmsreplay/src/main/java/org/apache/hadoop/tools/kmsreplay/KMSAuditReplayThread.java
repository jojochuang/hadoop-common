package org.apache.hadoop.tools.kmsreplay;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.CryptoCodec;
import org.apache.hadoop.crypto.Encryptor;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.crypto.key.kms.KMSClientProvider;
import org.apache.hadoop.hdfs.HdfsKMSUtil;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;

import static org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EEK;

public class KMSAuditReplayThread extends Thread {
  private static final Logger LOG =
      LoggerFactory.getLogger(KMSAuditReplayThread.class);

  private Mapper.Context mapperContext;
  private DelayQueue<AuditReplayCommand> commandQueue;
  Map<String, KeyProviderCryptoExtension> keyProviderCache;

  private long startTimestampMs;
  private Configuration mapperConf;
  // If any exception is encountered it will be stored here
  private Exception exception;
  private UserGroupInformation loginUser;

  // a cached KeyVersion
  private Map<String, KeyProviderCryptoExtension.EncryptedKeyVersion> cachedKeyVersion;

  KMSAuditReplayThread(Mapper.Context mapperContext, DelayQueue<AuditReplayCommand> commandQueue,
      Map<String, KeyProviderCryptoExtension> keyProviderCache) throws IOException {
    this.mapperContext = mapperContext;
    this.commandQueue = commandQueue;
    this.keyProviderCache = keyProviderCache;

    mapperConf = mapperContext.getConfiguration();
    startTimestampMs = mapperConf.getLong(KMSAuditReplayDriver.START_TIMESTAMP_MS, -1);

    loginUser = UserGroupInformation.getLoginUser();

    cachedKeyVersion = new ConcurrentHashMap<>();
  }

  /**
   * Add a command to this thread's processing queue.
   *
   * @param cmd Command to add.
   */
  void addToQueue(AuditReplayCommand cmd) {
    commandQueue.put(cmd);
  }

  /**
   * Get the Exception that caused this thread to stop running, if any, else
   * null. Should not be called until this thread has already completed (i.e.,
   * after {@link #join()} has been called).
   *
   * @return The exception which was thrown, if any.
   */
  Exception getException() {
    return exception;
  }

  @Override
  public void run() {
    long currentEpoch = System.currentTimeMillis();
    long delay = startTimestampMs - currentEpoch;
    try {
      if (delay > 0) {
        LOG.info("Sleeping for " + delay + " ms");
        Thread.sleep(delay);
      } else {
        LOG.warn("Starting late by " + (-1 * delay) + " ms");
      }

      AuditReplayCommand cmd = commandQueue.take();
      while (!cmd.isPoison()) {
        /*replayCountersMap.get(REPLAYCOUNTERS.TOTALCOMMANDS).increment(1);
        delay = cmd.getDelay(TimeUnit.MILLISECONDS);
        if (delay < -5) { // allow some tolerance here
          replayCountersMap.get(REPLAYCOUNTERS.LATECOMMANDS).increment(1);
          replayCountersMap.get(REPLAYCOUNTERS.LATECOMMANDSTOTALTIME)
              .increment(-1 * delay);
        }*/
        if (!replayLog(cmd)) {
          /*replayCountersMap.get(REPLAYCOUNTERS.TOTALINVALIDCOMMANDS)
              .increment(1);*/
        }
        cmd = commandQueue.take();
      }
    } catch (InterruptedException e) {
      LOG.error("Interrupted; exiting from thread.", e);
    } catch (Exception e) {
      exception = e;
      LOG.error("ReplayThread encountered exception; exiting.", e);
    }
  }

  /**
   * Attempt to replay the provided command. Updates counters accordingly.
   *
   * @param command The command to replay
   * @return True iff the command was successfully replayed (i.e., no exceptions
   *         were thrown).
   */
  @VisibleForTesting
  boolean replayLog(final AuditReplayCommand command) {
    LOG.info("replay command: " + command);
    KeyProviderCryptoExtension cachedKeyProvider = keyProviderCache.get(command.getUser());
    if (cachedKeyProvider == null) {
      UserGroupInformation ugi =
          UserGroupInformation.createProxyUser(command.getUser(), loginUser);
      cachedKeyProvider = ugi.doAs((PrivilegedAction<KeyProviderCryptoExtension>) () -> {
        KeyProvider keyProvider = null;
        try {
          keyProvider = HdfsKMSUtil.createKeyProvider(mapperConf);
        } catch (IOException ioe) {
          throw new RuntimeException(ioe);
        }
        if (keyProvider == null) {
          return null;
        }
        return KeyProviderCryptoExtension.createKeyProviderCryptoExtension(keyProvider);
      });
      keyProviderCache.put(command.getUser(), cachedKeyProvider);
    }
    AuditReplayMapper.KMSOp replayCommand;
    try {
      replayCommand = AuditReplayMapper.KMSOp.valueOf(
          command.getCommand().split(" ")[0].toUpperCase());
    } catch (IllegalArgumentException iae) {
      LOG.warn("Unsupported/invalid command: " + command);
      //replayCountersMap.get(REPLAYCOUNTERS.TOTALUNSUPPORTEDCOMMANDS).increment(1);
      return false;
    }

    try {
      long startTime = System.currentTimeMillis();
      switch (replayCommand) {
      case CREATE_KEY:
        cachedKeyProvider.createKey(command.getKey(), new KeyProvider.Options(mapperConf));
        break;
      case GET_KEYS:
        cachedKeyProvider.getKeys();
        break;
      case DELETE_KEY:
        cachedKeyProvider.deleteKey(command.getKey());
        break;
      case DECRYPT_EEK: {
        KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion =
            cachedKeyVersion.get(command.getKey());
        if (encryptedKeyVersion == null) {
          // if I don't have a cached keyVersion for this key, generate one and cache it.
          String key = command.getKey();
          KeyProviderCryptoExtension keyProviderCryptoExtension =
              KeyProviderCryptoExtension.createKeyProviderCryptoExtension(
                  new WrappedKeyProvider(cachedKeyProvider));
          // The WrappedKeyProvider is a hack to force use
          // DefaultCryptoExtension.generateEncryptedKey() because I don't
          // want it to talk to KMS which would incur lots of encrypted keys
          // due to cache.
          encryptedKeyVersion = keyProviderCryptoExtension.generateEncryptedKey(key);

          cachedKeyVersion.put(key, encryptedKeyVersion);
        }
        KeyProvider.KeyVersion decryptedKeyVersion =
            cachedKeyProvider.decryptEncryptedKey(encryptedKeyVersion);
        assert decryptedKeyVersion != null;
      }
        break;
      case GENERATE_EEK:
        // this would only come from NameNode
        String key = command.getKey();
        cachedKeyVersion.put(key, cachedKeyProvider.generateEncryptedKey(key));
        break;
      case GET_METADATA:
        cachedKeyProvider.getMetadata(command.getKey());
        break;
      //case REENCRYPT_EEK:
        //break;
      case GET_CURRENT_KEY:
        cachedKeyProvider.getCurrentKey(command.getKey());
        break;
      case GET_KEY_VERSION:
        KeyProvider.KeyVersion keyVersion = cachedKeyProvider.getKeyVersion(command.getKey());
        break;
      case GET_KEY_VERSIONS:
        cachedKeyProvider.getKeyVersions(command.getKey());
        break;
      case INVALIDATE_CACHE:
        cachedKeyProvider.invalidateCache(command.getKey());
        break;
      //case ROLL_NEW_VERSION:
        //break;
      case GET_KEYS_METADATA:
        // TODO: support multiple keys
        cachedKeyProvider.getKeysMetadata(command.getKey());
        break;
      //case REENCRYPT_EEK_BATCH:
        //break;
      default:
        throw new RuntimeException("Unexpected command: " + replayCommand);
      }
      //long latency = System.currentTimeMillis() - startTime;
      /*switch (replayCommand.getType()) {
      case WRITE:
        replayCountersMap.get(REPLAYCOUNTERS.TOTALWRITECOMMANDLATENCY).increment(latency);
        replayCountersMap.get(REPLAYCOUNTERS.TOTALWRITECOMMANDS).increment(1);
        break;
      case READ:
        replayCountersMap.get(REPLAYCOUNTERS.TOTALREADCOMMANDLATENCY).increment(latency);
        replayCountersMap.get(REPLAYCOUNTERS.TOTALREADCOMMANDS).increment(1);
        break;
      default:
        throw new RuntimeException("Unexpected command type: " + replayCommand.getType());
      }*/
      /*individualCommandsMap.get(replayCommand + INDIVIDUAL_COMMANDS_LATENCY_SUFFIX)
          .increment(latency);
      individualCommandsMap.get(replayCommand + INDIVIDUAL_COMMANDS_COUNT_SUFFIX).increment(1);*/
      return true;
    } catch (IOException e) {
      LOG.warn("IOException: " + e.getLocalizedMessage());
      //individualCommandsMap.get(replayCommand + INDIVIDUAL_COMMANDS_INVALID_SUFFIX).increment(1);
      return false;
    } catch (GeneralSecurityException e) {
      LOG.warn("GeneralSecurityException: " + e.getLocalizedMessage());
      return false;
    }
  }

  /**
   * Merge all of this thread's counter values into the counters contained
   * within the passed context.
   *
   * @param context The context holding the counters to increment.
   */
  void drainCounters(Mapper.Context context) {
    /*for (Map.Entry<REPLAYCOUNTERS, Counter> ent : replayCountersMap
        .entrySet()) {
      context.getCounter(ent.getKey()).increment(ent.getValue().getValue());
    }
    for (Map.Entry<String, Counter> ent : individualCommandsMap.entrySet()) {
      context.getCounter(INDIVIDUAL_COMMANDS_COUNTER_GROUP, ent.getKey())
          .increment(ent.getValue().getValue());
    }*/
  }

  private class WrappedKeyProvider extends KeyProvider {
    KeyProvider provider;
    protected WrappedKeyProvider(KeyProvider provider) {
      super(provider.getConf());
      this.provider = provider;
    }
    @Override public KeyVersion getKeyVersion(String versionName) throws IOException {
      return provider.getKeyVersion(versionName);
    }

    @Override public List<String> getKeys() throws IOException {
      return provider.getKeys();
    }

    @Override public List<KeyVersion> getKeyVersions(String name) throws IOException {
      return provider.getKeyVersions(name);
    }

    @Override public Metadata getMetadata(String name) throws IOException {
      return provider.getMetadata(name);
    }

    @Override public KeyVersion createKey(String name, byte[] material, Options options)
        throws IOException {
      return provider.createKey(name, material, options);
    }

    @Override public void deleteKey(String name) throws IOException {
      provider.deleteKey(name);
    }

    @Override public KeyVersion rollNewVersion(String name, byte[] material) throws IOException {
      return provider.rollNewVersion(name, material);
    }

    @Override public void flush() throws IOException {
      provider.flush();
    }
  }
}
