/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.tomcat.util.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.RejectedExecutionException;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.security.PrivilegedSetTccl;


/**
 * Handle incoming TCP connections.
 *
 * This class implement a simple server model: one listener thread accepts on a socket and
 * creates a new worker thread for each incoming connection.
 *
 * More advanced Endpoints will reuse the threads, use queues, etc.
 *
 * @author James Duncan Davidson
 * @author Jason Hunter
 * @author James Todd
 * @author Costin Manolache
 * @author Gal Shachor
 * @author Yoav Shapira
 * @author Remy Maucherat
 */
public class JIoEndpoint extends AbstractEndpoint<Socket> {


    // -------------------------------------------------------------- Constants

    private static final Log log = LogFactory.getLog(JIoEndpoint.class);

    // ----------------------------------------------------------------- Fields

    /**
     * Associated server socket.
     */
    protected ServerSocket serverSocket = null;


    // ------------------------------------------------------------ Constructor

    public JIoEndpoint() {
        // Set maxConnections to zero so we can tell if the user has specified
        // their own value on the connector when we reach bind()
        setMaxConnections(0);
        // Reduce the executor timeout for BIO as threads in keep-alive will not
        // terminate when the executor interrupts them.
        setExecutorTerminationTimeoutMillis(0);
    }

    // ------------------------------------------------------------- Properties

    /**
     * Handling of accepted sockets.
     */
    protected Handler handler = null;
    public void setHandler(Handler handler ) { this.handler = handler; }
    public Handler getHandler() { return handler; }

    /**
     * Server socket factory.
     */
    protected ServerSocketFactory serverSocketFactory = null;
    public void setServerSocketFactory(ServerSocketFactory factory) { this.serverSocketFactory = factory; }
    public ServerSocketFactory getServerSocketFactory() { return serverSocketFactory; }

    /**
     * Port in use.
     */
    @Override
    public int getLocalPort() {
        ServerSocket s = serverSocket;
        if (s == null) {
            return -1;
        } else {
            return s.getLocalPort();
        }
    }

    /*
     * Optional feature support.
     */
    @Override
    public boolean getUseSendfile() { return false; } // Not supported
    @Override
    public boolean getUseComet() { return false; } // Not supported
    @Override
    public boolean getUseCometTimeout() { return false; } // Not supported
    @Override
    public boolean getDeferAccept() { return false; } // Not supported
    @Override
    public boolean getUsePolling() { return false; } // Not supported


    // ------------------------------------------------ Handler Inner Interface

    /**
     * Bare bones interface used for socket processing. Per thread data is to be
     * stored in the ThreadWithAttributes extra folders, or alternately in
     * thread local fields.
     */
    public interface Handler extends AbstractEndpoint.Handler {
        public SocketState process(SocketWrapper<Socket> socket,
                SocketStatus status);
        public SSLImplementation getSslImplementation();
    }


    /**
     * Async timeout thread
     */
    protected class AsyncTimeout implements Runnable {
        /**
         * The background thread that checks async requests and fires the
         * timeout if there has been no activity.
         */
        @Override
        public void run() {

            // Loop until we receive a shutdown command
            while (running) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // Ignore
                }
                long now = System.currentTimeMillis();
                Iterator<SocketWrapper<Socket>> sockets =
                    waitingRequests.iterator();
                while (sockets.hasNext()) {
                    SocketWrapper<Socket> socket = sockets.next();
                    long access = socket.getLastAccess();
                    if (socket.getTimeout() > 0 &&
                            (now-access)>socket.getTimeout()) {
                        // Prevent multiple timeouts
                        socket.setTimeout(-1);
                        processSocketAsync(socket,SocketStatus.TIMEOUT);
                    }
                }

                // Loop if endpoint is paused
                while (paused && running) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }

            }
        }
    }


    // --------------------------------------------------- Acceptor Inner Class
    /**
     * The background thread that listens for incoming TCP/IP connections and
     * hands them off to an appropriate processor.
     */
    protected class Acceptor extends AbstractEndpoint.Acceptor {

        @Override
        public void run() {

            int errorDelay = 0;

            // Loop until we receive a shutdown command
            while (running) {

                // Loop if endpoint is paused
                while (paused && running) {
                    state = AcceptorState.PAUSED;
                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }

                if (!running) {
                    break;
                }
                state = AcceptorState.RUNNING;

                try {
                    //if we have reached max connections, wait
                    countUpOrAwaitConnection();

                    Socket socket = null;
                    try {
                        // Accept the next incoming connection from the server
                        // socket
                        socket = new DebugSocket(serverSocketFactory.acceptSocket(serverSocket));
                    } catch (IOException ioe) {
                        countDownConnection();
                        // Introduce delay if necessary
                        errorDelay = handleExceptionWithDelay(errorDelay);
                        // re-throw
                        throw ioe;
                    }
                    // Successful accept, reset the error delay
                    errorDelay = 0;

                    // Configure the socket
                    if (running && !paused && setSocketOptions(socket)) {
                        // Hand this socket off to an appropriate processor
                        if (!processSocket(socket)) {
                            countDownConnection();
                            // Close socket right away
                            closeSocket(socket);
                        }
                    } else {
                        countDownConnection();
                        // Close socket right away
                        closeSocket(socket);
                    }
                } catch (IOException x) {
                    if (running) {
                        log.error(sm.getString("endpoint.accept.fail"), x);
                    }
                } catch (NullPointerException npe) {
                    if (running) {
                        log.error(sm.getString("endpoint.accept.fail"), npe);
                    }
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    log.error(sm.getString("endpoint.accept.fail"), t);
                }
            }
            state = AcceptorState.ENDED;
        }
    }


    private void closeSocket(Socket socket) {
        try {
            socket.close();
        } catch (IOException e) {
            // Ignore
        }
    }


    // ------------------------------------------- SocketProcessor Inner Class


    /**
     * This class is the equivalent of the Worker, but will simply use in an
     * external Executor thread pool.
     */
    protected class SocketProcessor implements Runnable {

        protected SocketWrapper<Socket> socket = null;
        protected SocketStatus status = null;

        public SocketProcessor(SocketWrapper<Socket> socket) {
            if (socket==null) throw new NullPointerException();
            this.socket = socket;
        }

        public SocketProcessor(SocketWrapper<Socket> socket, SocketStatus status) {
            this(socket);
            this.status = status;
        }

        @Override
        public void run() {
            boolean launch = false;
            synchronized (socket) {
                try {
                    SocketState state = SocketState.OPEN;

                    try {
                        // SSL handshake
                        serverSocketFactory.handshake(socket.getSocket());
                    } catch (Throwable t) {
                        ExceptionUtils.handleThrowable(t);
                        if (log.isDebugEnabled()) {
                            log.debug(sm.getString("endpoint.err.handshake"), t);
                        }
                        // Tell to close the socket
                        state = SocketState.CLOSED;
                    }

                    if ((state != SocketState.CLOSED)) {
                        if (status == null) {
                            state = handler.process(socket, SocketStatus.OPEN_READ);
                        } else {
                            state = handler.process(socket,status);
                        }
                    }
                    if (state == SocketState.CLOSED) {
                        // Close socket
                        if (log.isTraceEnabled()) {
                            log.trace("Closing socket:"+socket);
                        }
                        countDownConnection();
                        try {
                            socket.getSocket().close();
                        } catch (IOException e) {
                            // Ignore
                        }
                    } else if (state == SocketState.OPEN ||
                            state == SocketState.UPGRADING ||
                            state == SocketState.UPGRADING_TOMCAT  ||
                            state == SocketState.UPGRADED){
                        socket.setKeptAlive(true);
                        socket.access();
                        launch = true;
                    } else if (state == SocketState.LONG) {
                        socket.access();
                        waitingRequests.add(socket);
                    }
                } finally {
                    if (launch) {
                        try {
                            getExecutor().execute(new SocketProcessor(socket, SocketStatus.OPEN_READ));
                        } catch (RejectedExecutionException x) {
                            log.warn("Socket reprocessing request was rejected for:"+socket,x);
                            try {
                                //unable to handle connection at this time
                                handler.process(socket, SocketStatus.DISCONNECT);
                            } finally {
                                countDownConnection();
                            }


                        } catch (NullPointerException npe) {
                            if (running) {
                                log.error(sm.getString("endpoint.launch.fail"),
                                        npe);
                            }
                        }
                    }
                }
            }
            socket = null;
            // Finish up this request
        }

    }


    // -------------------- Public methods --------------------

    @Override
    public void bind() throws Exception {

        // Initialize thread count defaults for acceptor
        if (acceptorThreadCount == 0) {
            acceptorThreadCount = 1;
        }
        // Initialize maxConnections
        if (getMaxConnections() == 0) {
            // User hasn't set a value - use the default
            setMaxConnections(getMaxThreadsExecutor(true));
        }

        if (serverSocketFactory == null) {
            if (isSSLEnabled()) {
                serverSocketFactory =
                    handler.getSslImplementation().getServerSocketFactory(this);
            } else {
                serverSocketFactory = new DefaultServerSocketFactory(this);
            }
        }

        if (serverSocket == null) {
            try {
                if (getAddress() == null) {
                    serverSocket = serverSocketFactory.createSocket(getPort(),
                            getBacklog());
                } else {
                    serverSocket = serverSocketFactory.createSocket(getPort(),
                            getBacklog(), getAddress());
                }
            } catch (BindException orig) {
                String msg;
                if (getAddress() == null)
                    msg = orig.getMessage() + " <null>:" + getPort();
                else
                    msg = orig.getMessage() + " " +
                            getAddress().toString() + ":" + getPort();
                BindException be = new BindException(msg);
                be.initCause(orig);
                throw be;
            }
        }

    }

    @Override
    public void startInternal() throws Exception {

        if (!running) {
            running = true;
            paused = false;

            // Create worker collection
            if (getExecutor() == null) {
                createExecutor();
            }

            initializeConnectionLatch();

            startAcceptorThreads();

            // Start async timeout thread
            Thread timeoutThread = new Thread(new AsyncTimeout(),
                    getName() + "-AsyncTimeout");
            timeoutThread.setPriority(threadPriority);
            timeoutThread.setDaemon(true);
            timeoutThread.start();
        }
    }

    @Override
    public void stopInternal() {
        releaseConnectionLatch();
        if (!paused) {
            pause();
        }
        if (running) {
            running = false;
            unlockAccept();
        }
        shutdownExecutor();
    }

    /**
     * Deallocate APR memory pools, and close server socket.
     */
    @Override
    public void unbind() throws Exception {
        if (running) {
            stop();
        }
        if (serverSocket != null) {
            try {
                if (serverSocket != null)
                    serverSocket.close();
            } catch (Exception e) {
                log.error(sm.getString("endpoint.err.close"), e);
            }
            serverSocket = null;
        }
        handler.recycle();
    }


    @Override
    protected AbstractEndpoint.Acceptor createAcceptor() {
        return new Acceptor();
    }


    /**
     * Configure the socket.
     */
    protected boolean setSocketOptions(Socket socket) {
        try {
            // 1: Set socket options: timeout, linger, etc
            socketProperties.setProperties(socket);
        } catch (SocketException s) {
            //error here is common if the client has reset the connection
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("endpoint.err.unexpected"), s);
            }
            // Close the socket
            return false;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            log.error(sm.getString("endpoint.err.unexpected"), t);
            // Close the socket
            return false;
        }
        return true;
    }


    /**
     * Process a new connection from a new client. Wraps the socket so
     * keep-alive and other attributes can be tracked and then passes the socket
     * to the executor for processing.
     *
     * @param socket    The socket associated with the client.
     *
     * @return          <code>true</code> if the socket is passed to the
     *                  executor, <code>false</code> if something went wrong or
     *                  if the endpoint is shutting down. Returning
     *                  <code>false</code> is an indication to close the socket
     *                  immediately.
     */
    protected boolean processSocket(Socket socket) {
        // Process the request from this socket
        try {
            SocketWrapper<Socket> wrapper = new SocketWrapper<Socket>(socket);
            wrapper.setKeepAliveLeft(getMaxKeepAliveRequests());
            wrapper.setSecure(isSSLEnabled());
            // During shutdown, executor may be null - avoid NPE
            if (!running) {
                return false;
            }
            getExecutor().execute(new SocketProcessor(wrapper));
        } catch (RejectedExecutionException x) {
            log.warn("Socket processing request was rejected for:"+socket,x);
            return false;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            // This means we got an OOM or similar creating a thread, or that
            // the pool and its queue are full
            log.error(sm.getString("endpoint.process.fail"), t);
            return false;
        }
        return true;
    }


    /**
     * Process an existing async connection. If processing is required, passes
     * the wrapped socket to an executor for processing.
     *
     * @param socket    The socket associated with the client.
     * @param status    Only OPEN and TIMEOUT are used. The others are used for
     *                  Comet requests that are not supported by the BIO (JIO)
     *                  Connector.
     */
    @Override
    public void processSocketAsync(SocketWrapper<Socket> socket,
            SocketStatus status) {
        try {
            synchronized (socket) {
                if (waitingRequests.remove(socket)) {
                    SocketProcessor proc = new SocketProcessor(socket,status);
                    ClassLoader loader = Thread.currentThread().getContextClassLoader();
                    try {
                        //threads should not be created by the webapp classloader
                        if (Constants.IS_SECURITY_ENABLED) {
                            PrivilegedAction<Void> pa = new PrivilegedSetTccl(
                                    getClass().getClassLoader());
                            AccessController.doPrivileged(pa);
                        } else {
                            Thread.currentThread().setContextClassLoader(
                                    getClass().getClassLoader());
                        }
                        // During shutdown, executor may be null - avoid NPE
                        if (!running) {
                            return;
                        }
                        getExecutor().execute(proc);
                        //TODO gotta catch RejectedExecutionException and properly handle it
                    } finally {
                        if (Constants.IS_SECURITY_ENABLED) {
                            PrivilegedAction<Void> pa = new PrivilegedSetTccl(loader);
                            AccessController.doPrivileged(pa);
                        } else {
                            Thread.currentThread().setContextClassLoader(loader);
                        }
                    }
                }
            }
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            // This means we got an OOM or similar creating a thread, or that
            // the pool and its queue are full
            log.error(sm.getString("endpoint.process.fail"), t);
        }
    }

    protected ConcurrentLinkedQueue<SocketWrapper<Socket>> waitingRequests =
        new ConcurrentLinkedQueue<SocketWrapper<Socket>>();
    @Override
    public void removeWaitingRequest(SocketWrapper<Socket> socketWrapper) {
        waitingRequests.remove(socketWrapper);
    }


    @Override
    protected Log getLog() {
        return log;
    }


    private static class DebugSocket extends Socket {

        private static final Log log = LogFactory.getLog(DebugSocket.class);

        private final Socket inner;


        public DebugSocket(Socket inner) {
            this.inner = inner;
            log.debug("DebugSocket [" + this.hashCode() +
                    "], inner Socket [" + inner.hashCode() +
                    "] for client port [" + inner.getPort() +
                    "]");
        }


        @Override
        public void connect(SocketAddress endpoint) throws IOException {
            log.debug("connect(SocketAddress)");
            try {
                inner.connect(endpoint);
            } catch (IOException e) {
                log.debug("connect(SocketAddress)", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("connect(SocketAddress)", e);
                throw e;
            }
        }


        @Override
        public void connect(SocketAddress endpoint, int timeout) throws IOException {
            log.debug("connect(SocketAddress,int)");
            try {
                inner.connect(endpoint, timeout);
            } catch (IOException e) {
                log.debug("connect(SocketAddress,int)", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("connect(SocketAddress,int)", e);
                throw e;
            }
        }


        @Override
        public void bind(SocketAddress bindpoint) throws IOException {
            log.debug("bind");
            try {
                inner.bind(bindpoint);
            } catch (IOException e) {
                log.debug("bind", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("bind", e);
                throw e;
            }
        }


        @Override
        public InetAddress getInetAddress() {
            log.debug("getInetAddress");
            try {
                return inner.getInetAddress();
            } catch (RuntimeException e) {
                log.debug("getInetAddress", e);
                throw e;
            }
        }


        @Override
        public InetAddress getLocalAddress() {
            log.debug("getLocalAddress");
            try {
                return inner.getLocalAddress();
            } catch (RuntimeException e) {
                log.debug("getLocalAddress", e);
                throw e;
            }
        }


        @Override
        public int getPort() {
            log.debug("getPort");
            try {
                return inner.getPort();
            } catch (RuntimeException e) {
                log.debug("getPort", e);
                throw e;
            }
        }


        @Override
        public int getLocalPort() {
            log.debug("getLocalPort");
            try {
                return inner.getLocalPort();
            } catch (RuntimeException e) {
                log.debug("getLocalPort", e);
                throw e;
            }
        }


        @Override
        public SocketAddress getRemoteSocketAddress() {
            log.debug("getRemoteSocketAddress");
            try {
                return inner.getRemoteSocketAddress();
            } catch (RuntimeException e) {
                log.debug("getRemoteSocketAddress", e);
                throw e;
            }
        }


        @Override
        public SocketAddress getLocalSocketAddress() {
            log.debug("getLocalSocketAddress");
            try {
                return inner.getLocalSocketAddress();
            } catch (RuntimeException e) {
                log.debug("getLocalSocketAddress", e);
                throw e;
            }
        }


        @Override
        public SocketChannel getChannel() {
            log.debug("getChannel");
            try {
                return inner.getChannel();
            } catch (RuntimeException e) {
                log.debug("getChannel", e);
                throw e;
            }
        }


        @Override
        public InputStream getInputStream() throws IOException {
            log.debug("getInputStream");
            try {
                return inner.getInputStream();
            } catch (IOException e) {
                log.debug("getInputStream", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getInputStream", e);
                throw e;
            }
        }


        @Override
        public OutputStream getOutputStream() throws IOException {
            try {
                OutputStream os = inner.getOutputStream();
                log.debug("DebugSocket [" + this.hashCode() +
                        "], inner Socket [" + inner.hashCode() +
                        "] has OutputStream [" + os.hashCode() +
                        "]");
                return os;
            } catch (IOException e) {
                log.debug("getOutputStream", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getOutputStream", e);
                throw e;
            }
        }


        @Override
        public void setTcpNoDelay(boolean on) throws SocketException {
            log.debug("setTcpNoDelay");
            try {
                inner.setTcpNoDelay(on);
            } catch (SocketException e) {
                log.debug("setTcpNoDelay", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setTcpNoDelay", e);
                throw e;
            }
        }


        @Override
        public boolean getTcpNoDelay() throws SocketException {
            log.debug("getTcpNoDelay");
            try {
                return inner.getTcpNoDelay();
            } catch (SocketException e) {
                log.debug("getTcpNoDelay", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getTcpNoDelay", e);
                throw e;
            }
        }


        @Override
        public void setSoLinger(boolean on, int linger) throws SocketException {
            log.debug("setSoLinger");
            try {
                inner.setSoLinger(on, linger);
            } catch (SocketException e) {
                log.debug("setSoLinger", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setSoLinger", e);
                throw e;
            }
        }


        @Override
        public int getSoLinger() throws SocketException {
            log.debug("getSoLinger");
            try {
                return inner.getSoLinger();
            } catch (SocketException e) {
                log.debug("getSoLinger", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getSoLinger", e);
                throw e;
            }
        }


        @Override
        public void sendUrgentData(int data) throws IOException {
            log.debug("sendUrgentData");
            try {
                inner.sendUrgentData(data);
            } catch (IOException e) {
                log.debug("sendUrgentData", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("sendUrgentData", e);
                throw e;
            }
        }


        @Override
        public void setOOBInline(boolean on) throws SocketException {
            log.debug("setOOBInline");
            try {
                inner.setOOBInline(on);
            } catch (SocketException e) {
                log.debug("setOOBInline", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setOOBInline", e);
                throw e;
            }
        }


        @Override
        public boolean getOOBInline() throws SocketException {
            log.debug("getOOBInline");
            try {
                return inner.getOOBInline();
            } catch (SocketException e) {
                log.debug("getOOBInline", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getOOBInline", e);
                throw e;
            }
        }


        @Override
        public synchronized void setSoTimeout(int timeout) throws SocketException {
            log.debug("setSoTimeout");
            try {
                inner.setSoTimeout(timeout);
            } catch (SocketException e) {
                log.debug("setSoTimeout", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setSoTimeout", e);
                throw e;
            }
        }


        @Override
        public synchronized int getSoTimeout() throws SocketException {
            log.debug("getSoTimeout");
            try {
                return inner.getSoTimeout();
            } catch (SocketException e) {
                log.debug("getSoTimeout", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getSoTimeout", e);
                throw e;
            }
        }


        @Override
        public synchronized void setSendBufferSize(int size) throws SocketException {
            log.debug("setSendBufferSize");
            try {
                inner.setSendBufferSize(size);
            } catch (SocketException e) {
                log.debug("setSendBufferSize", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setSendBufferSize", e);
                throw e;
            }
        }


        @Override
        public synchronized int getSendBufferSize() throws SocketException {
            log.debug("getSendBufferSize");
            try {
                return inner.getSendBufferSize();
            } catch (SocketException e) {
                log.debug("getSendBufferSize", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getSendBufferSize", e);
                throw e;
            }
        }


        @Override
        public synchronized void setReceiveBufferSize(int size) throws SocketException {
            log.debug("setReceiveBufferSize");
            try {
                inner.setReceiveBufferSize(size);
            } catch (SocketException e) {
                log.debug("setReceiveBufferSize", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setReceiveBufferSize", e);
                throw e;
            }
        }


        @Override
        public synchronized int getReceiveBufferSize() throws SocketException {
            log.debug("getReceiveBufferSize");
            try {
                return inner.getReceiveBufferSize();
            } catch (SocketException e) {
                log.debug("getReceiveBufferSize", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getReceiveBufferSize", e);
                throw e;
            }
        }


        @Override
        public void setKeepAlive(boolean on) throws SocketException {
            log.debug("setKeepAlive");
            try {
                inner.setKeepAlive(on);
            } catch (SocketException e) {
                log.debug("setKeepAlive", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setKeepAlive", e);
                throw e;
            }
        }


        @Override
        public boolean getKeepAlive() throws SocketException {
            log.debug("getKeepAlive");
            try {
                return inner.getKeepAlive();
            } catch (SocketException e) {
                log.debug("getKeepAlive", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getKeepAlive", e);
                throw e;
            }
        }


        @Override
        public void setTrafficClass(int tc) throws SocketException {
            log.debug("setTrafficClass");
            try {
                inner.setTrafficClass(tc);
            } catch (SocketException e) {
                log.debug("setTrafficClass", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setTrafficClass", e);
                throw e;
            }
        }


        @Override
        public int getTrafficClass() throws SocketException {
            log.debug("getTrafficClass");
            try {
                return inner.getTrafficClass();
            } catch (SocketException e) {
                log.debug("getTrafficClass", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getTrafficClass", e);
                throw e;
            }
        }


        @Override
        public void setReuseAddress(boolean on) throws SocketException {
            log.debug("setReuseAddress");
            try {
                inner.setReuseAddress(on);
            } catch (SocketException e) {
                log.debug("setReuseAddress", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("setReuseAddress", e);
                throw e;
            }
        }


        @Override
        public boolean getReuseAddress() throws SocketException {
            log.debug("getReuseAddress");
            try {
                return inner.getReuseAddress();
            } catch (SocketException e) {
                log.debug("getReuseAddress", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("getReuseAddress", e);
                throw e;
            }
        }


        @Override
        public synchronized void close() throws IOException {
            log.debug("close [" + this.hashCode() +
                    "], inner Socket [" + inner.hashCode() +
                    "]", new Exception());
            log.debug("bind");
            try {
                inner.close();
            } catch (IOException e) {
                log.debug("close", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("close", e);
                throw e;
            }
        }


        @Override
        public void shutdownInput() throws IOException {
            log.debug("shutdownInput");
            try {
                inner.shutdownInput();
            } catch (IOException e) {
                log.debug("shutdownInput", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("shutdownInput", e);
                throw e;
            }
        }


        @Override
        public void shutdownOutput() throws IOException {
            log.debug("shutdownOutput");
            try {
                inner.shutdownOutput();
            } catch (IOException e) {
                log.debug("shutdownOutput", e);
                throw e;
            } catch (RuntimeException e) {
                log.debug("shutdownOutput", e);
                throw e;
            }
        }


        @Override
        public String toString() {
            log.debug("toString");
            try {
                return inner.toString();
            } catch (RuntimeException e) {
                log.debug("toString", e);
                throw e;
            }
        }


        @Override
        public boolean isConnected() {
            log.debug("isConnected");
            try {
                return inner.isConnected();
            } catch (RuntimeException e) {
                log.debug("isConnected", e);
                throw e;
            }
        }


        @Override
        public boolean isBound() {
            log.debug("isBound");
            try {
                return inner.isBound();
            } catch (RuntimeException e) {
                log.debug("isBound", e);
                throw e;
            }
        }


        @Override
        public boolean isClosed() {
            log.debug("isClosed");
            try {
                return inner.isClosed();
            } catch (RuntimeException e) {
                log.debug("isClosed", e);
                throw e;
            }
        }


        @Override
        public boolean isInputShutdown() {
            log.debug("isInputShutdown");
            try {
                return inner.isInputShutdown();
            } catch (RuntimeException e) {
                log.debug("isInputShutdown", e);
                throw e;
            }
        }


        @Override
        public boolean isOutputShutdown() {
            log.debug("isOutputShutdown");
            try {
                return inner.isOutputShutdown();
            } catch (RuntimeException e) {
                log.debug("isOutputShutdown", e);
                throw e;
            }
        }


        @Override
        public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
            log.debug("setPerformancePreferences");
            try {
                inner.setPerformancePreferences(connectionTime, latency, bandwidth);
            } catch (RuntimeException e) {
                log.debug("setPerformancePreferences", e);
                throw e;
            }
        }
    }
}
