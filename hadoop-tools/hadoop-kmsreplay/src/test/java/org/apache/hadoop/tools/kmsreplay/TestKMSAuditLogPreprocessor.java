package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.JavaKeyStoreProvider;
import org.apache.hadoop.crypto.key.KeyProviderFactory;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.util.ToolRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.UUID;

import static org.junit.Assert.*;

public class TestKMSAuditLogPreprocessor {

  private static String TEST_ROOT_DIR = new File(System.getProperty(
      "test.build.data", "build/test/data"), UUID.randomUUID().toString())
      .getAbsolutePath();
  private File testRootDir;
  private Configuration conf = new Configuration();
  @Before
  public void setup() {
    testRootDir = new File(TEST_ROOT_DIR).getAbsoluteFile();


    final Path jksPath = new Path(testRootDir.toString(), "test.jks");
    final String ourUrl =
        JavaKeyStoreProvider.SCHEME_NAME + "://file" + jksPath.toUri();

    File file = new File(testRootDir, "test.jks");
    file.delete();
    conf.set(KeyProviderFactory.KEY_PROVIDER_PATH, ourUrl);
  }


  @Test
  public void test() throws Exception {
    // Use a local jks file as key provider, test it.
    String[] args = {"-a", System.getProperty("test.cache.data", "target/test-classes") +
        "/audit/kms-audit.log", "-e", "-v", "-o", TEST_ROOT_DIR + "/edek-dump"};
    KMSAuditLogPreprocessor driver = new KMSAuditLogPreprocessor();
    driver.setConf(conf);
    ToolRunner.run(driver, args);
  }

  @Test
  public void test2() throws Exception {
    // Use a local jks file as key provider, test it.
    String[] args = {"-a", System.getProperty("test.cache.data", "target/test-classes") +
        "/audit/kms-audit.log", "-c", "1"};
    KMSAuditLogPreprocessor driver = new KMSAuditLogPreprocessor();
    driver.setConf(conf);
    ToolRunner.run(driver, args);
  }
}