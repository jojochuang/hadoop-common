package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;

import java.io.IOException;
import java.util.function.Function;

public interface KMSAuditParser {
  /**
   * Initialize this parser with the given configuration. Guaranteed to be
   * called prior to any calls to {@link #parse(Text, Function)}.
   *
   * @param conf The Configuration to be used to set up this parser.
   */
  void initialize(Configuration conf) throws IOException;

  /**
   * Convert a line of input into an {@link AuditReplayCommand}. Since
   * {@link AuditReplayCommand}s store absolute timestamps, relativeToAbsolute
   * can be used to convert relative timestamps (i.e., milliseconds elapsed
   * between the start of the audit log and this command) into absolute
   * timestamps.
   *
   * @param inputLine Single input line to convert.
   * @param relativeToAbsolute Function converting relative timestamps
   *                           (in milliseconds) to absolute timestamps
   *                           (in milliseconds).
   * @return A command representing the input line.
   */
  AuditReplayCommand parse(Text inputLine,
      Function<Long, Long> relativeToAbsolute) throws IOException;
}
