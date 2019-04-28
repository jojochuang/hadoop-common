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

import io.jaegertracing.internal.JaegerTracer;
import io.opentracing.propagation.Format;
import io.opentracing.util.GlobalTracer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.MRJobConfig;
import org.apache.hadoop.mapreduce.filecache.DistributedCache;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat;
import org.apache.hadoop.mapreduce.lib.output.NullOutputFormat;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

public class KMSAuditReplayDriver extends Configured implements Tool {
  private static final Logger LOG =
      LoggerFactory.getLogger(KMSAuditReplayDriver.class);

  public static final String INPUT_PATH_KEY = "auditreplay.input_path";
  public static final String EDEK_DUMP_PATH_KEY = "edek_dump.input_path";
  public static final String START_TIMESTAMP_MS = "start_timestamp_ms";

  public static void main(String[] args) throws Exception {
    KMSAuditReplayDriver driver = new KMSAuditReplayDriver();
    System.exit(ToolRunner.run(driver, args));
  }

  @Override
  public int run(String[] args) throws Exception {

    parseArguments(args);

    Job job = getJobForSubmission(getConf());

    boolean success = job.waitForCompletion(true);
    return success ? 0 : 1;
  }

  void parseArguments(String[] args) {

  }

  /**
   * The format to save the context as text.
   * <p>
   * Using the mutable StringBuilder instead of plain String.
   */
  public static final class StringFormat implements Format<StringBuilder> {
  }

  private Job getJobForSubmission(Configuration baseConf)
      throws IOException, ClassNotFoundException, InstantiationException,
      IllegalAccessException {
    Configuration conf = new Configuration(baseConf);
    conf.setBoolean(MRJobConfig.MAP_SPECULATIVE, false);
    LOG.info("input path = " + conf.get(INPUT_PATH_KEY));
    Class<? extends AuditReplayMapper> mapperClass =
        org.apache.hadoop.tools.kmsreplay.AuditReplayMapper.class;

    /*String startTimeString = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss z")
        .format(new Date(startTimestampMs));
    LOG.info("The workload will start at " + startTimestampMs + " ms ("
        + startTimeString + ")");
    conf.setLong(START_TIMESTAMP_MS, startTimestampMs);*/

    Job job = Job.getInstance(conf, "KMS-o-meter Workload Driver");
    job.setOutputFormatClass(NullOutputFormat.class);
    job.setJarByClass(mapperClass);
    job.setMapperClass(mapperClass);
    job.setInputFormatClass(NoSplitTextInputFormat.class);
    job.setOutputFormatClass(NullOutputFormat.class);
    job.setNumReduceTasks(0);
    job.setMapOutputKeyClass(NullWritable.class);
    job.setMapOutputValueClass(NullWritable.class);
    job.setOutputKeyClass(NullWritable.class);
    job.setOutputValueClass(NullWritable.class);

    //DistributedCache.addFileToClassPath(TestMRJobs.APP_JAR, conf);

    return job;
  }

  /** A simple text input format that doesn't allow splitting of files. */
  public static class NoSplitTextInputFormat extends TextInputFormat {
    @Override
    public List<FileStatus> listStatus(JobContext context) throws IOException {
      context.getConfiguration().set(FileInputFormat.INPUT_DIR,
          context.getConfiguration().get(INPUT_PATH_KEY));
      return super.listStatus(context);
    }

    @Override
    public boolean isSplitable(JobContext context, Path file) {
      return false;
    }
  }
}