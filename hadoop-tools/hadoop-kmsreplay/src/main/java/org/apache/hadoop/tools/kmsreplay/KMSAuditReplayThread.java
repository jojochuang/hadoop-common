/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.tools.kmsreplay;

import com.google.common.annotations.VisibleForTesting;
import io.opentracing.Scope;
import io.opentracing.util.GlobalTracer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.KMSUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.hadoop.tools.kmsreplay.KMSAuditReplayDriver.NUM_ORIGINAL_KMS;

public class KMSAuditReplayThread extends Thread {
  private static final Logger LOG =
      LoggerFactory.getLogger(KMSAuditReplayThread.class);

  private Mapper.Context mapperContext;
  private DelayQueue<AuditReplayCommand> commandQueue;
  private Map<String, KeyProviderCryptoExtension> keyProviderCache;
  private AtomicInteger totalAuditCounter;
  private AtomicInteger auditReplayCounter;
  private boolean isNameNode;

  private long startTimestampMs;
  private Configuration mapperConf;
  // If any exception is encountered it will be stored here
  private Exception exception;
  private UserGroupInformation loginUser;

  // a cached KeyVersion
  private Map<String, KeyProviderCryptoExtension.EncryptedKeyVersion> cachedKeyVersion;
  private int generateEEKBatchSize = 150;
  // specify the number of KMSes in the original cluster
  private int numKMS = 2;

  KMSAuditReplayThread(Mapper.Context mapperContext, DelayQueue<AuditReplayCommand> commandQueue,
      Map<String, KeyProviderCryptoExtension> keyProviderCache,
      Map<String, KeyProviderCryptoExtension.EncryptedKeyVersion> cachedKeyVersion,
      AtomicInteger totalAuditCounter, AtomicInteger auditReplayCounter, boolean isNameNode) throws IOException {
    this.mapperContext = mapperContext;
    this.commandQueue = commandQueue;
    this.keyProviderCache = keyProviderCache;
    this.totalAuditCounter = totalAuditCounter;
    this.auditReplayCounter = auditReplayCounter;
    this.isNameNode = isNameNode;

    mapperConf = mapperContext.getConfiguration();
    startTimestampMs = mapperConf.getLong(KMSAuditReplayDriver.START_TIMESTAMP_MS, -1);

    loginUser = UserGroupInformation.getLoginUser();
    this.cachedKeyVersion = cachedKeyVersion;
    generateEEKBatchSize = (int)(mapperConf.getInt(
        CommonConfigurationKeysPublic.KMS_CLIENT_ENC_KEY_CACHE_SIZE,
        CommonConfigurationKeysPublic.
            KMS_CLIENT_ENC_KEY_CACHE_SIZE_DEFAULT) *
        mapperConf.getFloat(
            CommonConfigurationKeysPublic.
                KMS_CLIENT_ENC_KEY_CACHE_LOW_WATERMARK,
            CommonConfigurationKeysPublic.
                KMS_CLIENT_ENC_KEY_CACHE_LOW_WATERMARK_DEFAULT));
    numKMS = mapperConf.getInt(NUM_ORIGINAL_KMS, 1);
  }

  @VisibleForTesting
  void addCachedKeyVersionForTest(String key, KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion) {
    cachedKeyVersion.put(key, encryptedKeyVersion);
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

    Scope scope = null;
    if (!isNameNode) {
      scope = GlobalTracer.get().buildSpan("Simulated client").startActive(true);
    }
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
    } finally {
      if (scope != null) {
        scope.close();
      }
    }
  }

  private KeyProviderCryptoExtension getOrCreateKeyProvider(String user) {
    KeyProviderCryptoExtension cachedKeyProvider = keyProviderCache.get(user);
    if (cachedKeyProvider == null) {
      LOG.info("KeyProvider for user " + user + " doesn't exist yet. Create one ");
      UserGroupInformation ugi =
          UserGroupInformation.createProxyUser(user, loginUser);
      cachedKeyProvider = ugi.doAs((PrivilegedAction<KeyProviderCryptoExtension>) () -> {
        KeyProvider keyProvider = null;
        try {
          keyProvider = KMSUtil.createKeyProvider(mapperConf,
              CommonConfigurationKeysPublic.HADOOP_SECURITY_KEY_PROVIDER_PATH);
        } catch (IOException ioe) {
          throw new RuntimeException(ioe);
        }
        if (keyProvider == null) {
          LOG.warn("unable to create a key provider");
          return null;
        }
        return KeyProviderCryptoExtension.createKeyProviderCryptoExtension(keyProvider);
      });
      keyProviderCache.put(user, cachedKeyProvider);
    }
    return cachedKeyProvider;
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
    KeyProviderCryptoExtension cachedKeyProvider = getOrCreateKeyProvider(command.getUser());
    AuditReplayMapper.KMSOp replayCommand;
    try {
      replayCommand = AuditReplayMapper.KMSOp.valueOf(
          command.getCommand().split(" ")[0].toUpperCase());
    } catch (IllegalArgumentException iae) {
      LOG.warn("Unsupported/invalid command: " + command);
      //replayCountersMap.get(REPLAYCOUNTERS.TOTALUNSUPPORTEDCOMMANDS).increment(1);
      return false;
    }

    try (Scope scope = GlobalTracer.get().buildSpan("replayLog").startActive(true)) {
      scope.span().setTag("command", replayCommand.toString());
      scope.span().setTag("key", command.getKey());
      scope.span().setTag("user", command.getUser());
      scope.span().setTag("count", command.getAccessCount());

      for (int i = 0; i < command.getAccessCount(); i++) {
        if (command.getAccessCount() == 1 && command.getInterval() >= 1) {
          // This audit represents the start of an audit interval. Skip
          continue;
        }
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
            KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion = cachedKeyVersion.get(command.getKey());
            /*if (encryptedKeyVersion == null) {
              String key = command.getKey();
              encryptedKeyVersion = cachedKeyProvider.generateEncryptedKey(key);
              LOG.debug("created locally an eek and send to KMS to decrypt: " + key + "@"
                  + encryptedKeyVersion.getEncryptionKeyVersionName());
              cachedKeyVersion.put(key, encryptedKeyVersion);
            } else {*/
              LOG.debug("reuse existing eek for key " + command.getKey());
            /*}*/
            KeyProvider.KeyVersion decryptedKeyVersion = cachedKeyProvider.decryptEncryptedKey(encryptedKeyVersion);

            long endTime = System.currentTimeMillis();
            if (endTime - startTime > 1000) {
              LOG.warn("DECRYPT_EEK " + command.getKey() + " took " + (endTime - startTime) + " ms.");
            }
            assert decryptedKeyVersion != null;
            Thread.sleep(10 * 1000 / command.getAccessCount());
          }
          break;
          case GENERATE_EEK:
            // this would only come from NameNode
            String key = command.getKey();
            KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion = null;
            /*int numKMS = 1; // if something wrong with the reflection below, assume we have 1 KMS.
            try {
              Field extensionField = KeyProviderCryptoExtension.class.getDeclaredField("extension");
              extensionField.setAccessible(true);
              LoadBalancingKMSClientProvider kmsClientProvider =
                  (LoadBalancingKMSClientProvider)extensionField.get(cachedKeyProvider);
              numKMS = kmsClientProvider.getProviders().length;
            } catch (NoSuchFieldException e) {
              e.printStackTrace();
            } catch (IllegalAccessException e) {
              e.printStackTrace();
            }*/
            try (Scope scopeGenerate = GlobalTracer.get().buildSpan("generateEncryptedKey").startActive(true)) {
              scope.span().setTag("count", generateEEKBatchSize * numKMS);

              for (int gen = 0; gen < generateEEKBatchSize * numKMS; gen++) {
                encryptedKeyVersion = cachedKeyProvider.generateEncryptedKey(key);
              }
            }
            long endTime = System.currentTimeMillis();
            if (endTime - startTime > 1000) {
              LOG.warn("GENERATE_EEK " + command.getKey() + " took " + (endTime - startTime) + " ms.");
            }
            cachedKeyVersion.put(key, encryptedKeyVersion);

            // Note KMS has an internal EDEK cache (within KMSClientProvider).
            // but the GENERATE_EEK in  kms audit log are what actually hits KMS, which generates 150 EDEK at once.
            // So we should invalidate the internal cache to make sure each GENERATE_EEK request hits KMS.

            Thread.sleep(10 * 1000 / command.getAccessCount());
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
      }
    } catch(IOException e){
      LOG.warn("IOException: " + e.getLocalizedMessage());
      //individualCommandsMap.get(replayCommand + INDIVIDUAL_COMMANDS_INVALID_SUFFIX).increment(1);
      return false;
    } catch(GeneralSecurityException e){
      LOG.warn("GeneralSecurityException: " + e.getLocalizedMessage());
      return false;
    } catch(InterruptedException e){
      LOG.warn("InterruptedException: " + e.getLocalizedMessage());
    } finally{
      int replayed = auditReplayCounter.incrementAndGet();
      double percentReplayed = 100.0 * replayed / totalAuditCounter.get();
      mapperContext.setStatus(String.format("%.1f", percentReplayed) + "%:" + replayed + " replayed");
      if (replayed % 100 == 0) {
        LOG.info("Replayed " + replayed + " audits. Percent: " + String.format("%.1f", percentReplayed) + "%");
      }
    }
    return true;
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
}
