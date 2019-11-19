#!/usr/bin/env bash

#  generate kms audit logs and edek-dump
hadoop jar hadoop-kmsreplay-3.3.0-SNAPSHOT.jar \
    org.apache.hadoop.tools.kmsreplay.KMSAuditLogPreprocessor \
    -a kms-audit.log \
    -e \
    -o edek-dump \
    -c 8 \
    -v

# upload splitted audit logs to HDFS
sudo -u systest hdfs dfs -copyFromLocal kms-audit-generate_eek.log hdfs:///user/systest/audit/kms-audit.log.1


for i in {2..8}; do \
    sudo -u systest hdfs dfs -copyFromLocal kms-audit-decrypt_eek.log hdfs:///user/systest/audit/kms-audit.log.${i}; \
done

# copy edek-dump to HDFS
sudo -u systest hdfs dfs -copyFromLocal edek-dump hdfs:///user/systest/
