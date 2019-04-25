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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.MRJobConfig;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

public  class AuditReplayMapper
    extends Mapper<LongWritable, Text, NullWritable, NullWritable> {
  private static final Logger LOG =
      LoggerFactory.getLogger(AuditReplayMapper.class);

  private long startTimestampMs;
  private List<KMSAuditReplayThread> threads;
  private int numThreads;
  private long highestTimestamp;
  private KMSAuditParser commandParser;
  private Map<String, KeyProviderCryptoExtension> keyProviderCache;
  private Function<Long, Long> relativeToAbsoluteTimestamp;
  private double rateFactor;

  private DelayQueue<AuditReplayCommand> commandQueue;
  private ScheduledThreadPoolExecutor progressExecutor;

  private static final String NUM_THREADS_KEY = "auditreplay.num-threads";
  private static final int NUM_THREADS_DEFAULT = 1;
  public static final String RATE_FACTOR_KEY = "auditreplay.rate-factor";
  public static final double RATE_FACTOR_DEFAULT = 1.0;

  // This is the maximum amount that the mapper should read ahead from the input
  // as compared to the replay time. Setting this to one minute avoids reading
  // too
  // many entries into memory simultaneously but ensures that the replay threads
  // should not ever run out of entries to replay.
  private static final long MAX_READAHEAD_MS = 60000;

  public static final String COMMAND_PARSER_KEY =
      "auditreplay.command-parser.class";
  public static final Class<SimpleKMSAuditLogParser> COMMAND_PARSER_DEFAULT =
      SimpleKMSAuditLogParser.class;

  public enum KMSOp {
    CREATE_KEY, DELETE_KEY, ROLL_NEW_VERSION, INVALIDATE_CACHE,
    GET_KEYS, GET_KEYS_METADATA,
    GET_KEY_VERSIONS, GET_METADATA, GET_KEY_VERSION, GET_CURRENT_KEY,
    GENERATE_EEK, DECRYPT_EEK, REENCRYPT_EEK, REENCRYPT_EEK_BATCH
  }

  @Override
  public void setup(Context context) throws IOException, InterruptedException {
    Configuration conf = context.getConfiguration();

    startTimestampMs = conf.getLong(KMSAuditReplayDriver.START_TIMESTAMP_MS, -1);
    numThreads = conf.getInt(NUM_THREADS_KEY, NUM_THREADS_DEFAULT);
    rateFactor = conf.getDouble(RATE_FACTOR_KEY, RATE_FACTOR_DEFAULT);

    relativeToAbsoluteTimestamp =
        (input) -> startTimestampMs + Math.round(input / rateFactor);

    LOG.info("Starting " + numThreads + " threads");

    try {
      commandParser = conf.getClass(COMMAND_PARSER_KEY, COMMAND_PARSER_DEFAULT,
          KMSAuditParser.class).getConstructor().newInstance();
    } catch (NoSuchMethodException | InstantiationException
        | IllegalAccessException | InvocationTargetException e) {
      throw new IOException(
          "Exception encountered while instantiating the command parser", e);
    }
    commandParser.initialize(conf);

    progressExecutor = new ScheduledThreadPoolExecutor(1);
    // half of the timeout or once per minute if none specified
    long progressFrequencyMs = conf.getLong(MRJobConfig.TASK_TIMEOUT,
        2 * 60 * 1000) / 2;
    progressExecutor.scheduleAtFixedRate(context::progress,
        progressFrequencyMs, progressFrequencyMs, TimeUnit.MILLISECONDS);

    commandQueue = new DelayQueue<>();
    keyProviderCache = new ConcurrentHashMap<>();
    threads = new ArrayList<>();
    for (int t = 0; t < numThreads; t++) {
      KMSAuditReplayThread thread = new KMSAuditReplayThread(context, commandQueue, keyProviderCache);
      threads.add(thread);
      thread.start();
    }
  }

  @Override
  public void map(LongWritable lineNum, Text inputLine,
      Context context) throws IOException, InterruptedException {
    AuditReplayCommand cmd = commandParser.parse(inputLine,
        relativeToAbsoluteTimestamp);
    // if the command is unauthenticated, skip
    if (cmd == null) {
      return;
    }
    long delay = cmd.getDelay(TimeUnit.MILLISECONDS);
    // Prevent from loading too many elements into memory all at once
    if (delay > MAX_READAHEAD_MS) {
      Thread.sleep(delay - (MAX_READAHEAD_MS / 2));
    }
    commandQueue.put(cmd);
    highestTimestamp = cmd.getAbsoluteTimestamp();
  }

  @Override
  public void cleanup(Mapper.Context context) throws InterruptedException {
    for (KMSAuditReplayThread t : threads) {
      // Add in an indicator for each thread to shut down after the last real
      // command
      t.addToQueue(AuditReplayCommand.getPoisonPill(highestTimestamp + 1));
    }
    Optional<Exception> threadException = Optional.empty();
    for (KMSAuditReplayThread t : threads) {
      t.join();
      t.drainCounters(context);
      if (t.getException() != null) {
        threadException = Optional.of(t.getException());
      }
    }
    progressExecutor.shutdown();

    if (threadException.isPresent()) {
      throw new RuntimeException("Exception in AuditReplayThread",
          threadException.get());
    }
    /*LOG.info("Time taken to replay the logs in ms: "
        + (System.currentTimeMillis() - startTimestampMs));
    long totalCommands = context.getCounter(REPLAYCOUNTERS.TOTALCOMMANDS)
        .getValue();
    if (totalCommands != 0) {
      double percentageOfInvalidOps =
          context.getCounter(REPLAYCOUNTERS.TOTALINVALIDCOMMANDS).getValue()
              * 100.0 / totalCommands;
      LOG.info("Percentage of invalid ops: " + percentageOfInvalidOps);
    }*/
  }
}