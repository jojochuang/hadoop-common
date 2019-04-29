#!/bin/bash

HDFS_USER="systest"
# Create EZ keys, kms audit log file and edek-dump
hadoop jar hadoop-kmsreplay-3.3.0-SNAPSHOT.jar org.apache.hadoop.tools.kmsreplay.KMSAuditLogPreprocessor
    -a kms-audit.log \  # audit log input file
    -e \                # create encryption zone keys
    -v \                # create one EDEK per EZ key
    -o edek-dump        # output file for EDEK


# Upload edek-dump and kms-audit log to HDFS
hdfs dfs -mkdir hdfs:///user/${HDFS_USER}/audit

hdfs dfs -copyFromLocal kms-audit-generate_eek.log hdfs:///user/${HDFS_USER}/audit/kms-audit.log.1

for i in {2..8}; do hdfs dfs -copyFromLocal kms-audit-decrypt_eek.log hdfs:///user/${HDFS_USER}/audit/kms-audit.log.${i}; done

hdfs dfs -copyFromLocal edek-dump hdfs:///user/${HDFS_USER}/

# Load EZ dump for test
hadoop jar hadoop-kmsreplay-3.3.0-SNAPSHOT.jar org.apache.hadoop.tools.kmsreplay.KMSAuditLogPreprocessor \
    -l hdfs:///user/${HDFS_USER}/edek-dump

# Run
hadoop jar hadoop-kmsreplay-3.3.0-SNAPSHOT.jar org.apache.hadoop.tools.kmsreplay.KMSAuditReplayDriver \
    -Dauditreplay.input_path=hdfs:///user/${HDFS_USER}/audit \
    -Dauditreplay.log-start-time.ms=0 \
    -Dedek_dump.input_path=hdfs:///user/${HDFS_USER}/edek-dump
    # -DJAEGER_AGENT_HOST=epsilon-2.gce.cloudera.com -DJAEGER_AGENT_PORT=6831

