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
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.crypto.key.kms.LoadBalancingKMSClientProvider;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.util.KMSUtil;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static org.apache.hadoop.tools.kmsreplay.SimpleKMSAuditLogParser.AUDIT_START_TIMESTAMP_KEY;

/**
 * Preprocess KMS Audit log, split the audit log files into multiple, generate EDEK dump file.
 * Create encryption zone key and one EDEK per zone.
 */
public class KMSAuditLogPreprocessor extends Configured implements Tool {
  private static final Logger LOG =
      LoggerFactory.getLogger(KMSAuditLogPreprocessor.class);
  // SimpleKMSAuditLogger squashes similar audit events into one log.
  // This class expands the squashed audit log to multiple entries,
  // and split the file for KMS audit replayer to use

  KeyProviderCryptoExtension keyProvider;

  Set<String> accessedKey;

  private boolean createEncryptionKey;
  private boolean createEncryptedKeyVersion;
  private boolean dryRun;
  private String edekDumpFileName;
  private String auditInputFileName;
  private int numClients;

  private Function<Long, Long> relativeToAbsoluteTimestamp =
      (input) -> input;

  public static final String CREATE_ENCRYPTION_KEY = "createEncryptionKey";
  public static final String CREATE_ENCRYPTION_KEYVERSION = "createEncryptionKeyVersion";
  public static final String DRY_RUN = "dryRun";
  public static final String KMS_AUDIT_FILE = "auditFile";
  public static final String DEFAULT_KMS_AUDIT_FILE = "kms-audit.log";
  public static final String EDEK_DUMP_FILE = "edekDump";
  public static final String DEFAULT_EDEK_DUMP_FILE = "edek-dump";

  public static final String LOAD_EDEK_FILE = "loadEDEK";

  public static final String NUM_CLIENTS = "numClients";
  public static final int NUM_CLIENTS_DEFAULT = 10;

  private List<AuditReplayCommand> generateEEKCommandList =
      new ArrayList<>();

  public KMSAuditLogPreprocessor() {
    accessedKey = new HashSet<>();
  }

  public static void main(String[] args) throws Exception {
    KMSAuditLogPreprocessor driver = new KMSAuditLogPreprocessor();
    System.exit(ToolRunner.run(driver, args));
  }

  @Override
  public int run(String[] args) throws Exception {
    if (parseArguments(args) != 0) {
      return 1;
    }
    keyProvider = initializeKeyProvider();

    Configuration conf = getConf();
    conf.setLong(AUDIT_START_TIMESTAMP_KEY, 0);

    KMSAuditParser commandParser = new SimpleKMSAuditLogParser();
    commandParser.initialize(conf);

    String genFileName = "kms-audit-generate_eek.log";
    BufferedWriter genWriter = new BufferedWriter(new FileWriter(genFileName));
    String decFilePrefixName = "kms-audit-decrypt_eek.log";
    BufferedWriter[] decWriter = new BufferedWriter[numClients];
    for (int i = 0; i < numClients; i++) {
      decWriter[i] = new BufferedWriter(new FileWriter(decFilePrefixName + i));
    }
    // read file line by line
    try (BufferedReader reader = new BufferedReader(new FileReader(auditInputFileName))) {
      String line;
      while ((line = reader.readLine()) != null) {
        LOG.info("Reading line " + line);
        Text inputLine = new Text(line);
        AuditReplayCommand cmd = commandParser.parse(inputLine,
            relativeToAbsoluteTimestamp);
        // if the command is unauthenticated, skip
        if (cmd == null) {
          continue;
        }

        AuditReplayMapper.KMSOp replayCommand;
        try {
          replayCommand = AuditReplayMapper.KMSOp.valueOf(
              cmd.getCommand().split(" ")[0].toUpperCase());
        } catch (IllegalArgumentException iae) {
          LOG.warn("Unsupported/invalid command: " + cmd);
          //replayCountersMap.get(REPLAYCOUNTERS.TOTALUNSUPPORTEDCOMMANDS).increment(1);
          continue;
        }

        accessedKey.add(cmd.getKey());
        switch (replayCommand) {
          // NameNode only requests
          case GET_METADATA:
          case GENERATE_EEK:
            // all GENERATE_EEK comes from NN
            // expand audit log entries
            genWriter.append(line).append("\n");
            break;
        //case REENCRYPT_EEK_BATCH:
        //break;

            
          // Client-issued requests
          case DECRYPT_EEK:

          case CREATE_KEY: // used by KeyShell
          case GET_KEYS: // used by KeyShell
          case DELETE_KEY: // used by KeyShell
          case INVALIDATE_CACHE: // used by KeyShell
          case GET_KEYS_METADATA: // used by KeyShell
          case ROLL_NEW_VERSION: // used by KeyShell
            int extra = cmd.getAccessCount() % numClients;
            int accessCountPerClient = (cmd.getAccessCount()-extra) / numClients;
            AuditReplayCommand clientCommand = new AuditReplayCommand(
                cmd.getAbsoluteTimestamp(), cmd.getCommand(), cmd.getKey(),
                cmd.getUser(), accessCountPerClient, cmd.getInterval());
            for (int i = extra; i < numClients; i++) {
              decWriter[i].append(clientCommand.print());
            }
            clientCommand.setAccessCount(accessCountPerClient + 1);
            for (int i = 0; i < extra; i++) {
              decWriter[i].append(clientCommand.print());
            }

            break;

          // Not used by HDFS NN/clients
          /*case REENCRYPT_EEK:
          break;
          case GET_CURRENT_KEY:
            break;
          case GET_KEY_VERSION:
            break;
          case GET_KEY_VERSIONS:
            break;*/

          default:
            throw new RuntimeException("Unexpected command: " + replayCommand);
        }
        /*if (cmd.getCommand().equals("GENERATE_EEK")) {
          // all GENERATE_EEK comes from NN
          // expand audit log entries
          genWriter.append(line + "\n");
        } else {
          // if DECRYPT_EEK, remember the key.
          decWriter.append(line + "\n");
        }*/
      }
    }

    genWriter.close();
    for (BufferedWriter aDecWriter : decWriter) {
      aDecWriter.close();
    }

    // after read is done, create encryption keys, create EDEK of the keys
    if (createEncryptionKey) {
      createKey();
    }

    if (createEncryptedKeyVersion) {
      createAndSaveEncryptedKeyVersion();
    }

    return 0;
  }


  private int parseArguments(String[] args)
      throws ParseException, IOException, ClassNotFoundException {
    // parser configuration
    Option helpOption = new Option("h", "help", false,
        "Shows this message.");

    Option keyOption = new Option("e", CREATE_ENCRYPTION_KEY, false,
        "Create encryption keys accessed in the kms audit log.");

    Option keyValueOption = new Option("v", CREATE_ENCRYPTION_KEYVERSION, false,
        "Create EDEK for the encrypion key accessed in the kms audit log.");

    Option edekDumpOption = OptionBuilder.withArgName("output dump file name").hasArg()
        .withDescription("Specify the output file of the EDEK. Default: edek-dump")
        .withLongOpt(EDEK_DUMP_FILE)
        .create("o");

    Option dryRunOption = new Option("d", DRY_RUN, false,
        "Don't do anything for real.");

    Option kmsAuditFile = OptionBuilder.withArgName(KMS_AUDIT_FILE).hasArg()
        .withDescription("specify kms audit log file name. Default: kms-audit.log")
        .withLongOpt(KMS_AUDIT_FILE)
        .create("a");

    Option loadEDEKOption = OptionBuilder.withArgName("edek input dump file name").hasArg()
        .withDescription("Specify the input file of the EDEK. Default: edek-dump")
        .withLongOpt(LOAD_EDEK_FILE)
        .create("l");

    Option numClientsOption = OptionBuilder.withArgName("number of clients").hasArg()
        .withDescription("Specify number of clients (mapper) that will run in replayer. Default: 10")
        .withLongOpt(NUM_CLIENTS)
        .create("c");

    Options options = new Options();
    options.addOption(helpOption);
    options.addOption(keyOption);
    options.addOption(keyValueOption);
    options.addOption(edekDumpOption);
    options.addOption(dryRunOption);
    options.addOption(kmsAuditFile);
    options.addOption(loadEDEKOption);
    options.addOption(numClientsOption);

    CommandLineParser parser = new PosixParser();
    CommandLine cli = parser.parse(options, args, true);

    createEncryptionKey = cli.hasOption(CREATE_ENCRYPTION_KEY);
    createEncryptedKeyVersion = cli.hasOption(CREATE_ENCRYPTION_KEYVERSION);
    dryRun = cli.hasOption(DRY_RUN);

    if (cli.hasOption(KMS_AUDIT_FILE)) {
      auditInputFileName = cli.getOptionValue(KMS_AUDIT_FILE);
    } else {
      auditInputFileName = DEFAULT_KMS_AUDIT_FILE;
    }

    if (cli.hasOption(EDEK_DUMP_FILE)) {
      edekDumpFileName = cli.getOptionValue(EDEK_DUMP_FILE);
    } else {
      edekDumpFileName = DEFAULT_EDEK_DUMP_FILE;
    }

    if (cli.hasOption(NUM_CLIENTS)) {
      numClients = Integer.parseInt(cli.getOptionValue(NUM_CLIENTS));
    } else {
      numClients = NUM_CLIENTS_DEFAULT;
    }
    if (cli.hasOption("h") || args.length  == 0) {
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp(200,
          "./hadoop jar hadoop-kmsreplay-3.3.0-SNAPSHOT.jar org.apache.hadoop.tools.kmsreplay.KMSAuditLogPreprocessor [options]",
          null, options,
          null);

      return 1;
    } else if (cli.hasOption("l")) {
      String edekFileName = cli.getOptionValue(LOAD_EDEK_FILE);
      if (edekFileName == null) {
        edekFileName = DEFAULT_EDEK_DUMP_FILE;
      }
      loadEDEK(getConf(), edekFileName);
      return 1;
    }
    return 0;
  }

  public KeyProviderCryptoExtension initializeKeyProvider() {
    KeyProvider keyProvider = null;
    try {
      keyProvider = KMSUtil.createKeyProvider(getConf(),
          CommonConfigurationKeysPublic.HADOOP_SECURITY_KEY_PROVIDER_PATH);
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }
    if (keyProvider == null) {
      LOG.warn("unable to create a key provider");
      return null;
    }
    return KeyProviderCryptoExtension.createKeyProviderCryptoExtension(keyProvider);
  }

  public void createKey() throws IOException {
    LOG.info("There are " + accessedKey.size() + " encryption keys.");
    for (String keyName: accessedKey) {
      final KeyProvider.Options options = KeyProvider.options(getConf());

      if (dryRun) {
        LOG.info("DRY RUN: create key " + keyName);
      } else {
        try {
          keyProvider.createKey(keyName, options);

          LOG.info(
              keyName + " has been successfully created " + "with options " + options.toString() + ".");
        } catch (InvalidParameterException | IOException | NoSuchAlgorithmException e) {
          LOG.info(keyName + " was not been created due to " + e, e);
        }
      }
    }
    if (dryRun) {
      LOG.info("DRY RUN: flush key provider");
    } else {
      keyProvider.flush();
      LOG.info(keyProvider + " has been updated.");
    }
  }

  private void createAndSaveEncryptedKeyVersion() throws IOException, GeneralSecurityException {
    List<SerializableEncryptedKeyVersion> cachedKeyVersion = new ArrayList<>();
    try (FileOutputStream fileOut = new FileOutputStream(edekDumpFileName);
        ObjectOutputStream oout = new ObjectOutputStream(fileOut)) {
      for (String keyName : accessedKey) {
        if (dryRun) {
          LOG.info("DRY RUN: create EDEK for key " + keyName);
        } else {
          LOG.info("Saving EDEK of key " + keyName + " to file: " + edekDumpFileName);
          // create
          KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion =
              keyProvider.generateEncryptedKey(keyName);
          LOG.debug("generated EDEK: " + encryptedKeyVersion.getEncryptionKeyName() + "@"
              + encryptedKeyVersion.getEncryptionKeyVersionName());

          SerializableEncryptedKeyVersion serializableEncryptedKeyVersion =
              new SerializableEncryptedKeyVersion(encryptedKeyVersion);
          cachedKeyVersion.add(serializableEncryptedKeyVersion);
        }
      }

      // save
      oout.writeObject(cachedKeyVersion);
    }
  }

  // load EDEK dump file for test
  public static Map<String, KeyProviderCryptoExtension.EncryptedKeyVersion> loadEDEK(
      Configuration conf, String edekDumpFileName)
      throws IOException, ClassNotFoundException {
    List<SerializableEncryptedKeyVersion> keyVersionList;

    Map<String, KeyProviderCryptoExtension.EncryptedKeyVersion> cachedKeyVersion =
        new ConcurrentHashMap<>();

    if (edekDumpFileName.isEmpty()) {
      LOG.info("Skip loading EDEK because file name was not given");
      return cachedKeyVersion;
    }
    LOG.info("Loading EDEK from dump file " + edekDumpFileName);

    FileSystem fs = FileSystem.get(conf);

    try (FSDataInputStream fileIn = new FSDataInputStream(fs.open(new Path(edekDumpFileName)));
    //try (FileInputStream fileIn = new FileInputStream(edekDumpFileName);
        ObjectInputStream oin = new ObjectInputStream(fileIn)) {
      keyVersionList =
          (List<SerializableEncryptedKeyVersion>)oin.readObject();
      }

    for (SerializableEncryptedKeyVersion serializableEncryptedKeyVersion : keyVersionList) {
      KeyProviderCryptoExtension.EncryptedKeyVersion encryptedKeyVersion =
          KeyProviderCryptoExtension.EncryptedKeyVersion.createForDecryption(
              serializableEncryptedKeyVersion.encryptionKeyName,
              serializableEncryptedKeyVersion.encryptionKeyVersionName,
              serializableEncryptedKeyVersion.encryptedKeyIv,
              serializableEncryptedKeyVersion.material
          );
      cachedKeyVersion.put(encryptedKeyVersion.getEncryptionKeyName(), encryptedKeyVersion);
      LOG.info("Loaded key " + serializableEncryptedKeyVersion.getEncryptionKeyName());
    }

    return cachedKeyVersion;
  }
}
