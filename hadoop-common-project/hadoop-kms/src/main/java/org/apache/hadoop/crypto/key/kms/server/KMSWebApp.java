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
package org.apache.hadoop.crypto.key.kms.server;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.JmxReporter;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.CachingKeyProvider;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.crypto.key.KeyProviderFactory;
import org.apache.hadoop.crypto.key.TracerUtil;
import org.apache.hadoop.http.HttpServer2;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authorize.AccessControlList;
import org.apache.hadoop.util.VersionInfo;
import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;

@InterfaceAudience.Private
public class KMSWebApp implements ServletContextListener {

  private static final String LOG4J_PROPERTIES = "kms-log4j.properties";

  private static final String METRICS_PREFIX = "hadoop.kms.";
  private static final String ADMIN_CALLS_METER = METRICS_PREFIX +
      "admin.calls.meter";
  private static final String KEY_CALLS_METER = METRICS_PREFIX +
      "key.calls.meter";
  private static final String INVALID_CALLS_METER = METRICS_PREFIX +
      "invalid.calls.meter";
  private static final String UNAUTHORIZED_CALLS_METER = METRICS_PREFIX +
      "unauthorized.calls.meter";
  private static final String UNAUTHENTICATED_CALLS_METER = METRICS_PREFIX +
      "unauthenticated.calls.meter";
  private static final String GENERATE_EEK_METER = METRICS_PREFIX +
      "generate_eek.calls.meter";
  private static final String DECRYPT_EEK_METER = METRICS_PREFIX +
      "decrypt_eek.calls.meter";
  private static final String REENCRYPT_EEK_METER = METRICS_PREFIX +
      "reencrypt_eek.calls.meter";
  private static final String REENCRYPT_EEK_BATCH_METER = METRICS_PREFIX +
      "reencrypt_eek_batch.calls.meter";

  private static final String KEY_VALUE_CACHE_STAT = METRICS_PREFIX +
      "key_value_cache.stat";
  private static final String KEY_METADATA_CACHE_STAT = METRICS_PREFIX +
      "key_metadata_cache.stat";
  private static final String CURRENT_KEY_CACHE_STAT = METRICS_PREFIX +
      "current_key_cache.stat";

  private static final String KEY_VALUE_CACHE_HIT = METRICS_PREFIX +
      "key_value_cache.hit";
  private static final String KEY_METADATA_CACHE_HIT = METRICS_PREFIX +
      "key_metadata_cache.hit";
  private static final String CURRENT_KEY_CACHE_HIT = METRICS_PREFIX +
      "current_key_cache.hit";

  private static Logger LOG;
  private static MetricRegistry metricRegistry;

  private JmxReporter jmxReporter;
  private static Configuration kmsConf;
  private static KMSACLs kmsAcls;
  private static Meter adminCallsMeter;
  private static Meter keyCallsMeter;
  private static Meter unauthorizedCallsMeter;
  private static Meter unauthenticatedCallsMeter;
  private static Meter decryptEEKCallsMeter;
  private static Meter reencryptEEKCallsMeter;
  private static Meter reencryptEEKBatchCallsMeter;
  private static Meter generateEEKCallsMeter;
  private static Meter invalidCallsMeter;

  private static KMSAudit kmsAudit;
  private static KeyProviderCryptoExtension keyProviderCryptoExtension;

  static {
    SLF4JBridgeHandler.removeHandlersForRootLogger();
    SLF4JBridgeHandler.install();
  }

  private void initLogging(String confDir) {
    if (System.getProperty("log4j.configuration") == null) {
      System.setProperty("log4j.defaultInitOverride", "true");
      boolean fromClasspath = true;
      File log4jConf = new File(confDir, LOG4J_PROPERTIES).getAbsoluteFile();
      if (log4jConf.exists()) {
        PropertyConfigurator.configureAndWatch(log4jConf.getPath(), 1000);
        fromClasspath = false;
      } else {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        URL log4jUrl = cl.getResource(LOG4J_PROPERTIES);
        if (log4jUrl != null) {
          PropertyConfigurator.configure(log4jUrl);
        }
      }
      LOG = LoggerFactory.getLogger(KMSWebApp.class);
      LOG.debug("KMS log starting");
      if (fromClasspath) {
        LOG.warn("Log4j configuration file '{}' not found", LOG4J_PROPERTIES);
        LOG.warn("Logging with INFO level to standard output");
      }
    } else {
      LOG = LoggerFactory.getLogger(KMSWebApp.class);
    }
  }

  @Override
  public void contextInitialized(ServletContextEvent sce) {
    try {
      String confDir = System.getProperty(KMSConfiguration.KMS_CONFIG_DIR);
      if (confDir == null) {
        throw new RuntimeException("System property '" +
            KMSConfiguration.KMS_CONFIG_DIR + "' not defined");
      }
      kmsConf = KMSConfiguration.getKMSConf();
      initLogging(confDir);
      UserGroupInformation.setConfiguration(kmsConf);
      LOG.info("-------------------------------------------------------------");
      LOG.info("  Java runtime version : {}", System.getProperty(
          "java.runtime.version"));
      LOG.info("  User: {}", System.getProperty("user.name"));
      LOG.info("  KMS Hadoop Version: " + VersionInfo.getVersion());
      LOG.info("-------------------------------------------------------------");

      TracerUtil.initTracing(kmsConf, "KMS");

      kmsAcls = new KMSACLs();
      kmsAcls.startReloader();

      metricRegistry = new MetricRegistry();
      jmxReporter = JmxReporter.forRegistry(metricRegistry).build();
      jmxReporter.start();
      generateEEKCallsMeter = metricRegistry.register(GENERATE_EEK_METER,
          new Meter());
      decryptEEKCallsMeter = metricRegistry.register(DECRYPT_EEK_METER,
          new Meter());
      reencryptEEKCallsMeter = metricRegistry.register(REENCRYPT_EEK_METER,
          new Meter());
      reencryptEEKBatchCallsMeter = metricRegistry.register(
          REENCRYPT_EEK_BATCH_METER, new Meter());
      adminCallsMeter = metricRegistry.register(ADMIN_CALLS_METER, new Meter());
      keyCallsMeter = metricRegistry.register(KEY_CALLS_METER, new Meter());
      invalidCallsMeter = metricRegistry.register(INVALID_CALLS_METER,
          new Meter());
      unauthorizedCallsMeter = metricRegistry.register(UNAUTHORIZED_CALLS_METER,
          new Meter());
      unauthenticatedCallsMeter = metricRegistry.register(
          UNAUTHENTICATED_CALLS_METER, new Meter());

      kmsAudit = new KMSAudit(kmsConf);

      // this is required for the the JMXJsonServlet to work properly.
      // the JMXJsonServlet is behind the authentication filter,
      // thus the '*' ACL.
      sce.getServletContext().setAttribute(HttpServer2.CONF_CONTEXT_ATTRIBUTE,
          kmsConf);
      sce.getServletContext().setAttribute(HttpServer2.ADMINS_ACL,
          new AccessControlList(AccessControlList.WILDCARD_ACL_VALUE));

      // intializing the KeyProvider
      String providerString = kmsConf.get(KMSConfiguration.KEY_PROVIDER_URI);
      if (providerString == null) {
        throw new IllegalStateException("No KeyProvider has been defined");
      }
      KeyProvider keyProvider =
          KeyProviderFactory.get(new URI(providerString), kmsConf);
      if (kmsConf.getBoolean(KMSConfiguration.KEY_CACHE_ENABLE,
          KMSConfiguration.KEY_CACHE_ENABLE_DEFAULT)) {
        long keyTimeOutMillis =
            kmsConf.getLong(KMSConfiguration.KEY_CACHE_TIMEOUT_KEY,
                KMSConfiguration.KEY_CACHE_TIMEOUT_DEFAULT);
        long currKeyTimeOutMillis =
            kmsConf.getLong(KMSConfiguration.CURR_KEY_CACHE_TIMEOUT_KEY,
                KMSConfiguration.CURR_KEY_CACHE_TIMEOUT_DEFAULT);
        keyProvider = new CachingKeyProvider(keyProvider, keyTimeOutMillis,
            currKeyTimeOutMillis);

        final KeyProvider finalKeyProvider = keyProvider;
        metricRegistry.register(
            KEY_VALUE_CACHE_STAT, new Gauge<String>() {
              @Override
              public String getValue() {
                return ((CachingKeyProvider)finalKeyProvider).getKeyVersionCacheStat().toString();
              }
            });

        metricRegistry.register(
            KEY_METADATA_CACHE_STAT, new Gauge<String>() {
              @Override
              public String getValue() {
                return ((CachingKeyProvider)finalKeyProvider).getKeyMetadataCacheStat().toString();
              }
            });

        metricRegistry.register(
            CURRENT_KEY_CACHE_STAT, new Gauge<String>() {
              @Override
              public String getValue() {
                return ((CachingKeyProvider)finalKeyProvider).getCurrentKeyCacheStat().toString();
              }
            });

        metricRegistry.register(
            KEY_VALUE_CACHE_HIT, new Gauge<Integer>() {
              @Override
              public Integer getValue() {
                return ((CachingKeyProvider)finalKeyProvider).getKeyVersionCacheHit();
              }
            });

        metricRegistry.register(
            KEY_METADATA_CACHE_HIT, new Gauge<Integer>() {
              @Override
              public Integer getValue() {
                return ((CachingKeyProvider)finalKeyProvider).getKeyMetadataCacheHit();
              }
            });

        metricRegistry.register(
            CURRENT_KEY_CACHE_HIT, new Gauge<Integer>() {
              @Override
              public Integer getValue() {
                return ((CachingKeyProvider)finalKeyProvider).getCurrentKeyCacheHit();
              }
            });
      }
      LOG.info("Initialized KeyProvider " + keyProvider);

      keyProviderCryptoExtension = KeyProviderCryptoExtension.
          createKeyProviderCryptoExtension(keyProvider);
      keyProviderCryptoExtension =
          new EagerKeyGeneratorKeyProviderCryptoExtension(kmsConf,
              keyProviderCryptoExtension);
      if (kmsConf.getBoolean(KMSConfiguration.KEY_AUTHORIZATION_ENABLE,
          KMSConfiguration.KEY_AUTHORIZATION_ENABLE_DEFAULT)) {
        keyProviderCryptoExtension =
            new KeyAuthorizationKeyProvider(
                keyProviderCryptoExtension, kmsAcls);
      }
        
      LOG.info("Initialized KeyProviderCryptoExtension "
          + keyProviderCryptoExtension);
      final int defaultBitlength = kmsConf
          .getInt(KeyProvider.DEFAULT_BITLENGTH_NAME,
              KeyProvider.DEFAULT_BITLENGTH);
      LOG.info("Default key bitlength is {}", defaultBitlength);
      LOG.info("KMS Started");
    } catch (Throwable ex) {
      System.out.println();
      System.out.println("ERROR: Hadoop KMS could not be started");
      System.out.println();
      System.out.println("REASON: " + ex.toString());
      System.out.println();
      System.out.println("Stacktrace:");
      System.out.println("---------------------------------------------------");
      ex.printStackTrace(System.out);
      System.out.println("---------------------------------------------------");
      System.out.println();
      System.exit(1);
    }
  }

  @Override
  public void contextDestroyed(ServletContextEvent sce) {
    try {
      keyProviderCryptoExtension.close();
    } catch (IOException ioe) {
      LOG.error("Error closing KeyProviderCryptoExtension", ioe);
    }
    kmsAudit.shutdown();
    kmsAcls.stopReloader();
    jmxReporter.stop();
    jmxReporter.close();
    metricRegistry = null;
    LOG.info("KMS Stopped");
  }

  public static Configuration getConfiguration() {
    return new Configuration(kmsConf);
  }

  public static KMSACLs getACLs() {
    return kmsAcls;
  }

  public static Meter getAdminCallsMeter() {
    return adminCallsMeter;
  }

  public static Meter getKeyCallsMeter() {
    return keyCallsMeter;
  }

  public static Meter getInvalidCallsMeter() {
    return invalidCallsMeter;
  }

  public static Meter getGenerateEEKCallsMeter() {
    return generateEEKCallsMeter;
  }

  public static Meter getDecryptEEKCallsMeter() {
    return decryptEEKCallsMeter;
  }

  public static Meter getReencryptEEKCallsMeter() {
    return reencryptEEKCallsMeter;
  }

  public static Meter getReencryptEEKBatchCallsMeter() {
    return reencryptEEKBatchCallsMeter;
  }

  public static Meter getUnauthorizedCallsMeter() {
    return unauthorizedCallsMeter;
  }

  public static Meter getUnauthenticatedCallsMeter() {
    return unauthenticatedCallsMeter;
  }

  public static KeyProviderCryptoExtension getKeyProvider() {
    return keyProviderCryptoExtension;
  }

  public static KMSAudit getKMSAudit() {
    return kmsAudit;
  }
}
