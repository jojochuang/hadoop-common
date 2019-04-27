# KMS-o-Meter

KMS-o-Meter is a workload replay tool for Hadoop's Key Management Server.

This tool is inspired by LinkedIn's [Dynamometer](https://github.com/linkedin/dynamometer).

## Build
go to hadoop-tools/hadoop-kmsreplay/ directory
```bash
mvn install -DskipTests
```
It creates a hadoop-kmsreplay jar file which is essentially a MapReduce job that can run on a Hadoop cluster to send requests to KMS.

## Usage
Pre-requisite: the cluster must have KMS installed and configured.

Parse kms-audit.log file, for each encryption key referenced in the audit, create the key, generate one EDEK per key, and store them into an EDEK dump,

```bash
jar hadoop-kmsreplay-3.3.0-SNAPSHOT.jar \
org.apache.hadoop.tools.kmsreplay.KMSAuditLogPreprocessor \
-a kms-audit.log  -e -v -o edek-dump
```

Create a GENERATE_EEK-less kms audit log file, and another kms audit that contains only GENERATE_EEK

```bash
grep -v "GENERATE_EEK" kms-audit.log > kms-audit-decrypt_eek.log
grep "GENERATE_EEK" kms-audit.log > kms-audit-generate_eek.log
```
Upload kms-audit-decrypt_eek.log, kms-audit-generate_eek.log and edek-dump to HDFS.

```bash
hdfs dfs -copyFromLocal kms-audit-generate_eek.log \
hdfs:///user/systest/audit/kms-audit.log.1

for i in {2..8}; do hdfs dfs -copyFromLocal kms-audit-decrypt_eek.log \
hdfs:///user/systest/audit/kms-audit.log.${i}; done

hdfs dfs -copyFromLocal edek-dump hdfs:///user/systest/

```

The number of audit files under hdfs:///user/systest/audit determines the number of mappers that workload replayer creates.

```bash
hadoop jar hadoop-kmsreplay-3.3.0-SNAPSHOT.jar org.apache.hadoop.tools.kmsreplay.KMSAuditReplayDriver \
 -Dauditreplay.input_path=hdfs:///user/systest/audit \
 -Dauditreplay.log-start-time.ms=0 \
 -Dedek_dump.input_path=hdfs:///user/systest/edek-dump
```

The mapper that gets the GENERATE_EEK audits simulates a NameNode, and other mappers simulates clients.
The EDEK dump file is a representation of NameNode.

## License
Apache License 2.0