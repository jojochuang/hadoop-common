package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.kms.server.KeyAuthorizationKeyProvider;
import org.apache.hadoop.crypto.key.kms.server.TestKMS;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.ToolRunner;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.UUID;

import static org.junit.Assert.*;

public class TestKMSAuditReplay extends TestKMS {
  private static final Logger LOG =
      LoggerFactory.getLogger(TestKMSAuditReplay.class);

  private static String TEST_ROOT_DIR = new File(System.getProperty(
      "test.build.data", "build/test/data"), UUID.randomUUID().toString())
      .getAbsolutePath();

  private static final String KMS_AUDIT_LOG_DIR = "target/test-classes/audit";

  @Test
  public void test() throws Exception {
    if (!new File(TEST_ROOT_DIR).mkdirs()) {
      throw new RuntimeException("Could not create test dir: " + TEST_ROOT_DIR);
    }

    KMSCallable<Integer> callable = new KMSCallable<Integer>() {
      @Override public Integer call() throws Exception {
        JobConf conf = new JobConf();
        final URI uri = createKMSUri(getKMSUrl());
        conf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_KEY_PROVIDER_PATH, uri.toString());

        UserGroupInformation proxyUgi = null;
        proxyUgi = UserGroupInformation.createRemoteUser("client");
        UserGroupInformation.setLoginUser(proxyUgi);


        conf.set("mapreduce.framework.name", "local");
        conf.setLong("auditreplay.log-start-time.ms", 0);//1555891200000);
        conf.set("auditreplay.input_path", KMS_AUDIT_LOG_DIR);

        KMSAuditReplayDriver driver = new KMSAuditReplayDriver();

        driver.setConf(conf);
        return ToolRunner.run(driver, new String[] {});
      }
    };

    int ret = startKMSWithCallable(callable);

    assertEquals("return value not zero", 0, ret);
  }

  public int startKMSWithCallable(KMSCallable<Integer> callable) throws Exception {
    Configuration conf = new Configuration();
    final File testDir = new File(TEST_ROOT_DIR);
    conf = createBaseKMSConf(testDir, conf);
    conf.set("hadoop.kms.authentication.type", "simple");
    conf.set("default.key.acl.MANAGEMENT", "*");
    conf.set("default.key.acl.GENERATE_EEK", "*");
    conf.set("default.key.acl.DECRYPT_EEK", "*");
    conf.set("default.key.acl.READ", "*");

    writeConf(testDir, conf);

    return runServer(null, null, testDir, callable);
  }
}