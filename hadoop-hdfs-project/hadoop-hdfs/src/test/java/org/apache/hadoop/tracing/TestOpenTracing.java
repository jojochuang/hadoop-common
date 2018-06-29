package org.apache.hadoop.tracing;


import io.opentracing.Scope;
import io.opentracing.Tracer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FsTracer;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.util.Random;

public class TestOpenTracing {
  private static Tracer tracer;
  private static Scope scope;

  private static MiniDFSCluster cluster = null;
  private static FileSystem fs;
  private static Configuration conf = new HdfsConfiguration();

  @BeforeClass
  public static void setUp() throws Exception {
    tracer = FsTracer.get(null);
    scope = tracer.buildSpan("TestHDFSTrash").startActive(true);

    try (Scope setupScope = tracer.buildSpan("setup").startActive(true)) {

      cluster = new MiniDFSCluster.Builder(conf).numDataNodes(3).build();
      fs = FileSystem.get(conf);
    }

  }

  @AfterClass
  public static void tearDown() {
    if (cluster != null) { cluster.shutdown(); }
    scope.close();
  }

  @Test
  public void testWrite() throws IOException {
    try (Scope scope = tracer.buildSpan("testTrace").startActive(true)) {
      Path path = new Path("/smallfile");
      try (FSDataOutputStream fdos = fs.create(path)) {
        int fileSize = 2048;
        final long seed = 0xDEADBEEFL;
        byte[] buffer = new byte[fileSize];
        Random rand = new Random(seed);
        rand.nextBytes(buffer);
        fdos.write(buffer);
      }
    }
  }
}
