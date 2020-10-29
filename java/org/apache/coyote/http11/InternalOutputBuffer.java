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

package org.apache.coyote.http11;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

import org.apache.coyote.OutputBuffer;
import org.apache.coyote.Response;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SocketWrapper;

/**
 * Output buffer.
 *
 * @author <a href="mailto:remm@apache.org">Remy Maucherat</a>
 */
public class InternalOutputBuffer extends AbstractOutputBuffer<Socket>
    implements ByteChunk.ByteOutputChannel {

    private static final Log log = LogFactory.getLog(InternalOutputBuffer.class);

    // ----------------------------------------------------------- Constructors

    /**
     * Default constructor.
     */
    public InternalOutputBuffer(Response response, int headerBufferSize) {

        this.response = response;

        buf = new byte[headerBufferSize];

        outputStreamOutputBuffer = new OutputStreamOutputBuffer();

        filterLibrary = new OutputFilter[0];
        activeFilters = new OutputFilter[0];
        lastActiveFilter = -1;

        socketBuffer = new ByteChunk();
        socketBuffer.setByteOutputChannel(this);

        if (log.isDebugEnabled()) {
            log.debug("Creating InternalOutputBuffer [" + this.hashCode() +
                    "] with OutputStreamOutputBuffer [" + outputStreamOutputBuffer.hashCode() +
                    "], socketBuffer [" + socketBuffer.hashCode() + "]");
        }
        committed = false;
        finished = false;

    }

    /**
     * Underlying output stream. Note: protected to assist with unit testing
     */
    protected OutputStream outputStream;


    /**
     * Socket buffer.
     */
    private ByteChunk socketBuffer;


    /**
     * Socket buffer (extra buffering to reduce number of packets sent).
     */
    private boolean useSocketBuffer = false;


    /**
     * Set the socket buffer size.
     */
    public void setSocketBuffer(int socketBufferSize) {

        if (socketBufferSize > 500) {
            useSocketBuffer = true;
            socketBuffer.allocate(socketBufferSize, socketBufferSize);
            log.debug("Setting socket buffer size for InternalOutputBuffer [" + this.hashCode() +
                    "] with OutputStreamOutputBuffer [" + outputStreamOutputBuffer.hashCode() +
                    "] to [" + socketBufferSize +
                    "], socketBuffer is enabled, socketBuffer is [" + socketBuffer.hashCode() +
                    "], underlying byte[] is [" + socketBuffer.getBuffer().hashCode() + "]");
        } else {
            useSocketBuffer = false;
            log.debug("Setting socket buffer size for InternalOutputBuffer [" + this.hashCode() +
                    "] with OutputStreamOutputBuffer [" + outputStreamOutputBuffer.hashCode() +
                    "] to [" + socketBufferSize +
                    "], socketBuffer is disabled]");
        }

    }


    // --------------------------------------------------------- Public Methods

    @Override
    public void init(SocketWrapper<Socket> socketWrapper,
            AbstractEndpoint<Socket> endpoint) throws IOException {

        outputStream = socketWrapper.getSocket().getOutputStream();

        log.debug("Creating outputStream for InternalOutputBuffer [" + this.hashCode() +
                "], client port is [" + socketWrapper.getSocket().getPort() +
                "], outputStream is [" + outputStream.hashCode() + "]");
    }


    /**
     * Flush the response.
     *
     * @throws IOException an underlying I/O error occurred
     */
    @Override
    public void flush()
        throws IOException {

        super.flush();

        // Flush the current buffer
        if (useSocketBuffer) {
            socketBuffer.flushBuffer();
        }

    }


    /**
     * Recycle the output buffer. This should be called when closing the
     * connection.
     */
    @Override
    public void recycle() {
        super.recycle();
        outputStream = null;
        log.debug("Recycling InternalOutputBuffer [" + this.hashCode() + "]");
    }


    /**
     * End processing of current HTTP request.
     * Note: All bytes of the current request should have been already
     * consumed. This method only resets all the pointers so that we are ready
     * to parse the next HTTP request.
     */
    @Override
    public void nextRequest() {
        super.nextRequest();
        socketBuffer.recycle();
        log.debug("InternalOutputBuffer [" + this.hashCode() + "]");
    }


    /**
     * End request.
     *
     * @throws IOException an underlying I/O error occurred
     */
    @Override
    public void endRequest()
        throws IOException {
        super.endRequest();
        if (useSocketBuffer) {
            socketBuffer.flushBuffer();
        }
        log.debug("InternalOutputBuffer [" + this.hashCode() + "]");
    }


    // ------------------------------------------------ HTTP/1.1 Output Methods


    /**
     * Send an acknowledgment.
     */
    @Override
    public void sendAck()
        throws IOException {

        if (!committed)
            outputStream.write(Constants.ACK_BYTES);

    }


    // ------------------------------------------------------ Protected Methods


    /**
     * Commit the response.
     *
     * @throws IOException an underlying I/O error occurred
     */
    @Override
    protected void commit()
        throws IOException {

        // The response is now committed
        committed = true;
        response.setCommitted(true);

        if (pos > 0) {
            // Sending the response header buffer
            if (useSocketBuffer) {
                socketBuffer.append(buf, 0, pos);
                log.debug("Writing headers of length [" + pos +
                        "] for InternalOutputBuffer [" + this.hashCode() +
                        "] to socketBuffer [" + socketBuffer.hashCode() +
                        "], underlying byte[] is [" + socketBuffer.getBuffer().hashCode() + "]");
            } else {
                outputStream.write(buf, 0, pos);
                log.debug("Writing headers of length [" + pos +
                        "] for InternalOutputBuffer [" + this.hashCode() +
                        "] to outputStream [" + outputStream.hashCode() + "]");
            }
        }

    }


    /**
     * Callback to write data from the buffer.
     */
    @Override
    public void realWriteBytes(byte cbuf[], int off, int len)
        throws IOException {
        if (len > 0) {
            outputStream.write(cbuf, off, len);
            log.debug("Writing body of length [" + len +
                    "] from byte[] [" + cbuf.hashCode() +
                    "] for InternalOutputBuffer [" + this.hashCode() +
                    "] to outputStream [" + outputStream.hashCode() + "]");
        }
    }


    // ----------------------------------- OutputStreamOutputBuffer Inner Class


    /**
     * This class is an output buffer which will write data to an output
     * stream.
     */
    protected class OutputStreamOutputBuffer
        implements OutputBuffer {


        /**
         * Write chunk.
         */
        @Override
        public int doWrite(ByteChunk chunk, Response res)
            throws IOException {

            int length = chunk.getLength();
            if (useSocketBuffer) {
                socketBuffer.append(chunk.getBuffer(), chunk.getStart(),
                                    length);
                log.debug("Writing body of length [" + length +
                        "] from ByteChunk [" + chunk.hashCode() +
                        "] with underlying byte[] [" + chunk.getBuffer().hashCode() +
                        "] for InternalOutputBuffer [" + InternalOutputBuffer.this.hashCode() +
                        "] and OutputStreamOutputBuffer [" + this.hashCode() +
                        "] to socketBuffer [" + socketBuffer.hashCode() +
                        "] with underlying byte[] [" + socketBuffer.getBuffer().hashCode() + "]");
            } else {
                outputStream.write(chunk.getBuffer(), chunk.getStart(),
                                   length);
                log.debug("Writing body of length [" + length +
                        "] from ByteChunk [" + chunk.hashCode() +
                        "] with underlying byte[] [" + chunk.getBuffer().hashCode() +
                        "] for InternalOutputBuffer [" + InternalOutputBuffer.this.hashCode() +
                        "] and OutputStreamOutputBuffer [" + this.hashCode() +
                        "] to outputStream [" + outputStream.hashCode() + "]");
            }
            byteCount += chunk.getLength();
            return chunk.getLength();
        }

        @Override
        public long getBytesWritten() {
            return byteCount;
        }
    }
}
