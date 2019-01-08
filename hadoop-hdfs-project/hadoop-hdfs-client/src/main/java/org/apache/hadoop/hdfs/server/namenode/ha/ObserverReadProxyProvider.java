/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdfs.server.namenode.ha;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.permission.FsAction;
import org.apache.hadoop.hdfs.ClientGSIContext;
import org.apache.hadoop.hdfs.client.HdfsClientConfigKeys;
import org.apache.hadoop.hdfs.protocol.ClientProtocol;
import org.apache.hadoop.hdfs.protocol.LocatedBlock;
import org.apache.hadoop.ipc.AlignmentContext;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.ipc.RemoteException;
import org.apache.hadoop.ipc.StandbyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.VisibleForTesting;

/**
 * A {@link org.apache.hadoop.io.retry.FailoverProxyProvider} implementation
 * that supports reading from observer namenode(s).
 *
 * This constructs a wrapper proxy that sends the request to observer
 * namenode(s), if observer read is enabled. In case there are multiple
 * observer namenodes, it will try them one by one in case the RPC failed. It
 * will fail back to the active namenode after it has exhausted all the
 * observer namenodes.
 *
 * Read and write requests will still be sent to active NN if reading from
 * observer is turned off.
 */
public class ObserverReadProxyProvider<T extends ClientProtocol>
    extends AbstractNNFailoverProxyProvider<T> {
  private static final Logger LOG = LoggerFactory.getLogger(
      ObserverReadProxyProvider.class);

  /** Client-side context for syncing with the NameNode server side */
  private AlignmentContext alignmentContext;

  private AbstractNNFailoverProxyProvider<T> failoverProxy;
  /** All NameNdoe proxies */
  private List<NNProxyInfo<T>> nameNodeProxies =
      new ArrayList<NNProxyInfo<T>>();
  /** Proxies for the observer namenodes */
  private final List<NNProxyInfo<T>> observerProxies =
      new ArrayList<NNProxyInfo<T>>();

  /**
   * Whether reading from observer is enabled. If this is false, all read
   * requests will still go to active NN.
   */
  private boolean observerReadEnabled;

  /**
   * Thread-local index to record the current index in the observer list.
   */
  private static final ThreadLocal<Integer> currentIndex =
      ThreadLocal.withInitial(() -> 0);

  /** The last proxy that has been used. Only used for testing */
  private volatile ProxyInfo<T> lastProxy = null;

  /**
   * By default ObserverReadProxyProvider uses
   * {@link ConfiguredFailoverProxyProvider} for failover.
   */
  public ObserverReadProxyProvider(
      Configuration conf, URI uri, Class<T> xface, HAProxyFactory<T> factory)
      throws IOException {
    this(conf, uri, xface, factory,
        new ConfiguredFailoverProxyProvider<T>(conf, uri, xface,factory));
  }

  public ObserverReadProxyProvider(
      Configuration conf, URI uri, Class<T> xface, HAProxyFactory<T> factory,
      AbstractNNFailoverProxyProvider<T> failoverProxy)
      throws IOException {
    super(conf, uri, xface, factory);
    this.failoverProxy = failoverProxy;
    this.alignmentContext = new ClientGSIContext();
    ((ClientHAProxyFactory<T>) factory).setAlignmentContext(alignmentContext);

    // Get all NameNode proxies
    nameNodeProxies = getProxyAddresses(uri,
        HdfsClientConfigKeys.DFS_NAMENODE_RPC_ADDRESS_KEY);
    // Find out all the observer proxies
    for (NNProxyInfo<T> pi : nameNodeProxies) {
      createProxyIfNeeded(pi);
      if (isObserverState(pi)) {
        observerProxies.add(pi);
      }
    }

    // TODO: No observers is not an error
    // Just direct all reads go to the active NameNode
    if (observerProxies.isEmpty()) {
      throw new RuntimeException("Couldn't find any namenode proxy in " +
          "OBSERVER state");
    }
  }

  public synchronized AlignmentContext getAlignmentContext() {
    return alignmentContext;
  }

  @SuppressWarnings("unchecked")
  @Override
  public synchronized ProxyInfo<T> getProxy() {
    // We just create a wrapped proxy containing all the proxies
    StringBuilder combinedInfo = new StringBuilder("[");

    for (int i = 0; i < this.observerProxies.size(); i++) {
      if (i > 0) {
        combinedInfo.append(",");
      }
      combinedInfo.append(observerProxies.get(i).proxyInfo);
    }

    combinedInfo.append(']');
    T wrappedProxy = (T) Proxy.newProxyInstance(
        ObserverReadInvocationHandler.class.getClassLoader(),
        new Class<?>[]{xface},
        new ObserverReadInvocationHandler(observerProxies));
    return new ProxyInfo<>(wrappedProxy, combinedInfo.toString());
  }

  @Override
  public void performFailover(T currentProxy) {
    failoverProxy.performFailover(currentProxy);
  }

  /**
   * Check if a method is read-only.
   *
   * @return whether the 'method' is a read-only operation.
   */
  private boolean isRead(Method method) {
    return method.isAnnotationPresent(ReadOnly.class);
  }

  @VisibleForTesting
  void setObserverReadEnabled(boolean flag) {
    this.observerReadEnabled = flag;
  }

  /**
   * After getting exception 'ex', whether we should retry the current request
   * on a different observer.
   */
  private boolean shouldRetry(Exception ex) throws Exception {
    // TODO: implement retry policy
    return true;
  }

  @VisibleForTesting
  ProxyInfo<T> getLastProxy() {
    return lastProxy;
  }

  boolean isObserverState(NNProxyInfo<T> pi) {
    // TODO: should introduce new ClientProtocol method to verify the
    // underlying service state, which does not require superuser access
    // The is a workaround
    IOException ioe = null;
    try {
      // Verify write access first
      pi.proxy.reportBadBlocks(new LocatedBlock[0]);
      return false; // Only active NameNode allows write
    } catch (RemoteException re) {
      IOException sbe = re.unwrapRemoteException(StandbyException.class);
      if (!(sbe instanceof StandbyException)) {
        ioe = re;
      }
    } catch (IOException e) {
      ioe = e;
    }
    if (ioe != null) {
      LOG.error("Failed to connect to {}", pi.getAddress(), ioe);
      return false;
    }
    // Verify read access
    // For now we assume only Observer nodes allow reads
    // Stale reads on StandbyNode should be turned off
    try {
      pi.proxy.checkAccess("/", FsAction.READ);
      return true;
    } catch (RemoteException re) {
      IOException sbe = re.unwrapRemoteException(StandbyException.class);
      if (!(sbe instanceof StandbyException)) {
        ioe = re;
      }
    } catch (IOException e) {
      ioe = e;
    }
    if (ioe != null) {
      LOG.error("Failed to connect to {}", pi.getAddress(), ioe);
    }
    return false;
  }


  class ObserverReadInvocationHandler implements InvocationHandler {
    final List<NNProxyInfo<T>> observerProxies;
    final ProxyInfo<T> activeProxy;

    ObserverReadInvocationHandler(List<NNProxyInfo<T>> observerProxies) {
      this.observerProxies = observerProxies;
      this.activeProxy = failoverProxy.getProxy();
    }

    /**
     * Sends read operations to the observer (if enabled) specified by the
     * current index, and send write operations to the active. If a observer
     * fails, we increment the index and retry the next one. If all observers
     * fail, the request is forwarded to the active.
     *
     * Write requests are always forwarded to the active.
     */
    @Override
    public Object invoke(Object proxy, final Method method, final Object[] args)
        throws Throwable {
      lastProxy = null;
      Object retVal;

      if (observerReadEnabled && isRead(method)) {
        // Loop through all the proxies, starting from the current index.
        for (int i = 0; i < observerProxies.size(); i++) {
          NNProxyInfo<T> current = observerProxies.get(currentIndex.get());
          try {
            retVal = method.invoke(current.proxy, args);
            lastProxy = current;
            return retVal;
          } catch (Exception e) {
            if (!shouldRetry(e)) {
              throw e;
            }
            currentIndex.set((currentIndex.get() + 1) % observerProxies.size());
            LOG.warn("Invocation returned exception on [{}]",
                current.proxyInfo, e.getCause());
          }
        }

        // If we get here, it means all observers have failed.
        LOG.warn("All observers have failed for read request {}. " +
            "Fall back on active: {}", method.getName(), activeProxy);
      }

      // Either all observers have failed, or that it is a write request.
      // In either case, we'll forward the request to active NameNode.
      try {
        retVal = method.invoke(activeProxy.proxy, args);
      } catch (Exception e) {
        throw e.getCause();
      }
      lastProxy = activeProxy;
      return retVal;
    }
  }

  @Override
  public synchronized void close() throws IOException {
    failoverProxy.close();
    for (ProxyInfo<T> pi : nameNodeProxies) {
      if (pi.proxy != null) {
        if (pi.proxy instanceof Closeable) {
          ((Closeable)pi.proxy).close();
        } else {
          RPC.stopProxy(pi.proxy);
        }
      }
    }
  }

  @Override
  public boolean useLogicalURI() {
    return failoverProxy.useLogicalURI();
  }
}
