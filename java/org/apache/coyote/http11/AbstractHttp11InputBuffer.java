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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.coyote.InputBuffer;
import org.apache.coyote.Request;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.HeaderUtil;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.res.StringManager;

/**
 * Abstract base implementation of InputBuffer for HTTP that provides request
 * header parsing as well as transfer encoding.
 */
public abstract class AbstractHttp11InputBuffer implements InputBuffer, ApplicationBufferHandler {

    /**
     * The string manager for this package.
     */
    private static final StringManager sm = StringManager.getManager(AbstractHttp11InputBuffer.class);


    protected static final byte[] CLIENT_PREFACE_START =
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);


    /**
     * Associated Coyote request.
     */
    protected final Request request;

    /**
     * Headers of the associated request.
     */
    protected final MimeHeaders headers;

    /**
     * Maximum allowed size of the HTTP request line plus headers plus any
     * leading blank lines.
     */
    protected final int headerBufferSize;

    protected final boolean rejectIllegalHeader;

    protected final HttpParser httpParser;

    /**
     * Swallow input ? (in the case of an expectation)
     */
    protected boolean swallowInput;

    /**
     * The read buffer.
     */
    protected ByteBuffer byteBuffer;

    /**
     * Wrapper that provides access to the underlying socket.
     */
    protected SocketWrapperBase<?> wrapper;

    /**
     * Underlying input buffer.
     */
    protected InputBuffer inputStreamInputBuffer;

    /**
     * Filter library.
     * Note: Filter[Constants.CHUNKED_FILTER] is always the "chunked" filter.
     */
    protected InputFilter[] filterLibrary;

    /**
     * Active filters (in order).
     */
    protected InputFilter[] activeFilters;

    /**
     * Index of the last active filter.
     */
    protected int lastActiveFilter;

    /*
     * Parsing state.
     */
    protected volatile boolean parsingHeader;
    protected byte prevChr = 0;
    protected byte chr = 0;
    protected int parsingRequestLinePhase = 0;
    protected final HeaderParseData headerData = new HeaderParseData();
    /**
     * Pos of the end of the header in the buffer, which is also the
     * start of the body.
     */
    protected int end;

    /**
     * Known size of the read buffer.
     */
    protected int socketReadBufferSize;


    // ----------------------------------------------------------- Constructors

    protected AbstractHttp11InputBuffer(Request request, int headerBufferSize,
            boolean rejectIllegalHeader, HttpParser httpParser) {

        this.request = request;
        headers = request.getMimeHeaders();
        this.headerBufferSize = headerBufferSize;
        this.rejectIllegalHeader = rejectIllegalHeader;
        this.httpParser = httpParser;

        filterLibrary = new InputFilter[0];
        activeFilters = new InputFilter[0];
        lastActiveFilter = -1;

        parsingHeader = true;
        parsingRequestLinePhase = 0;
        swallowInput = true;
    }


    // ------------------------------------------------------------- Properties

    /**
     * Add an input filter to the filter library.
     *
     * @throws NullPointerException if the supplied filter is null
     */
    protected void addFilter(InputFilter filter) {

        if (filter == null) {
            throw new NullPointerException(sm.getString("iib.filter.npe"));
        }

        InputFilter[] newFilterLibrary = Arrays.copyOf(filterLibrary, filterLibrary.length + 1);
        newFilterLibrary[filterLibrary.length] = filter;
        filterLibrary = newFilterLibrary;

        activeFilters = new InputFilter[filterLibrary.length];
    }


    /**
     * Get filters.
     */
    protected InputFilter[] getFilters() {
        return filterLibrary;
    }


    /**
     * Add an input filter to the filter library.
     */
    protected void addActiveFilter(InputFilter filter) {

        if (lastActiveFilter == -1) {
            filter.setBuffer(inputStreamInputBuffer);
        } else {
            for (int i = 0; i <= lastActiveFilter; i++) {
                if (activeFilters[i] == filter) {
                    return;
                }
            }
            filter.setBuffer(activeFilters[lastActiveFilter]);
        }

        activeFilters[++lastActiveFilter] = filter;

        filter.setRequest(request);
    }


    @Override
    public void setByteBuffer(ByteBuffer buffer) {
        byteBuffer = buffer;
    }


    @Override
    public ByteBuffer getByteBuffer() {
        return byteBuffer;
    }


    @Override
    public void expand(int size) {
        if (byteBuffer.capacity() >= size) {
            byteBuffer.limit(size);
        }
        ByteBuffer temp = ByteBuffer.allocate(size);
        temp.put(byteBuffer);
        byteBuffer = temp;
        byteBuffer.mark();
        temp = null;
    }


    /**
     * Set the swallow input flag.
     */
    protected void setSwallowInput(boolean swallowInput) {
        this.swallowInput = swallowInput;
    }


    // ---------------------------------------------------- InputBuffer Methods

    @Override
    public int doRead(ApplicationBufferHandler handler) throws IOException {
        if (lastActiveFilter == -1) {
            return inputStreamInputBuffer.doRead(handler);
        } else {
            return activeFilters[lastActiveFilter].doRead(handler);
        }
    }


    // ------------------------------------------------------- Protected Methods

    protected void init(SocketWrapperBase<?> socketWrapper) {

        wrapper = socketWrapper;
        wrapper.setAppReadBufHandler(this);

        int bufLength = headerBufferSize +
                wrapper.getSocketBufferHandler().getReadBuffer().capacity();
        if (byteBuffer == null || byteBuffer.capacity() < bufLength) {
            byteBuffer = ByteBuffer.allocate(bufLength);
            byteBuffer.position(0).limit(0);
        }
    }


    /**
     * Recycle the input buffer. This should be called when closing the
     * connection.
     */
    protected void recycle() {
        wrapper = null;
        request.recycle();

        for (int i = 0; i <= lastActiveFilter; i++) {
            activeFilters[i].recycle();
        }

        byteBuffer.limit(0).position(0);
        lastActiveFilter = -1;
        swallowInput = true;

        chr = 0;
        prevChr = 0;
        parsingRequestLinePhase = 0;
        headerData.recycle();

    }


    /**
     * End processing of current HTTP request.
     * Note: All bytes of the current request should have been already
     * consumed. This method only resets all the pointers so that we are ready
     * to parse the next HTTP request.
     */
    protected void nextRequest() {
        request.recycle();

        if (byteBuffer.position() > 0) {
            if (byteBuffer.remaining() > 0) {
                // Copy leftover bytes to the beginning of the buffer
                byteBuffer.compact();
                byteBuffer.flip();
            } else {
                // Reset position and limit to 0
                byteBuffer.position(0).limit(0);
            }
        }

        // Recycle filters
        for (int i = 0; i <= lastActiveFilter; i++) {
            activeFilters[i].recycle();
        }

        // Reset pointers
        lastActiveFilter = -1;
        parsingHeader = true;
        swallowInput = true;

        parsingRequestLinePhase = 0;
    }


    protected abstract boolean parseRequestLine(boolean keptAlive, int connectionTimeout, int keepAliveTimeout)
            throws IOException;


    protected String parseInvalid(int startPos, ByteBuffer buffer) {
        // Look for the next space
        byte b = 0;
        while (buffer.hasRemaining() && b != 0x20) {
            b = buffer.get();
        }
        String result = HeaderUtil.toPrintableString(buffer.array(), buffer.arrayOffset() + startPos, buffer.position() - startPos);
        if (b != 0x20) {
            // Ran out of buffer rather than found a space
            result = result + "...";
        }
        return result;
    }


    protected int getParsingRequestLinePhase() {
        return parsingRequestLinePhase;
    }


    /**
     * Parse the HTTP headers.
     */
    protected boolean parseHeaders() throws IOException {
        if (!parsingHeader) {
            throw new IllegalStateException(sm.getString("iib.parseheaders.ise.error"));
        }

        HeaderParseStatus status = HeaderParseStatus.HAVE_MORE_HEADERS;

        do {
            status = parseHeader();
            // Checking that
            // (1) Headers plus request line size does not exceed its limit
            // (2) There are enough bytes to avoid expanding the buffer when
            // reading body
            // Technically, (2) is technical limitation, (1) is logical
            // limitation to enforce the meaning of headerBufferSize
            // From the way how buf is allocated and how blank lines are being
            // read, it should be enough to check (1) only.
            if (byteBuffer.position() > headerBufferSize || byteBuffer.capacity() - byteBuffer.position() < socketReadBufferSize) {
                throw new IllegalArgumentException(sm.getString("iib.requestheadertoolarge.error"));
            }
        } while (status == HeaderParseStatus.HAVE_MORE_HEADERS);
        if (status == HeaderParseStatus.DONE) {
            parsingHeader = false;
            end = byteBuffer.position();
            return true;
        } else {
            return false;
        }
    }


    /**
     * Parse an HTTP header.
     *
     * @return One of {@link HeaderParseStatus#NEED_MORE_DATA},
     * {@link HeaderParseStatus#HAVE_MORE_HEADERS} or
     * {@link HeaderParseStatus#DONE}.
     */
    protected abstract HeaderParseStatus parseHeader() throws IOException;


    @Override
    public int available() {
        return available(false);
    }


    protected abstract int available(boolean doRead);


    protected boolean isChunking() {
        for (int i = 0; i < lastActiveFilter; i++) {
            if (activeFilters[i] == filterLibrary[Constants.CHUNKED_FILTER]) {
                return true;
            }
        }
        return false;
    }


    /**
     * Has all of the request body been read? There are subtle differences
     * between this and available() &gt; 0 primarily because of having to handle
     * faking non-blocking reads with the blocking IO connector.
     */
    protected boolean isFinished() {
        // The active filters have the definitive information on whether or not
        // the current request body has been read. Note that byteBuffer may
        // contain pipelined data so is not a good indicator.
        if (lastActiveFilter >= 0) {
            return activeFilters[lastActiveFilter].isFinished();
        } else {
            // No filters. Assume request is not finished. EOF will signal end of
            // request.
            return false;
        }
    }


    protected ByteBuffer getLeftover() {
        int available = byteBuffer.remaining();
        if (available > 0) {
            return ByteBuffer.wrap(byteBuffer.array(), byteBuffer.position(), available);
        } else {
            return null;
        }
    }


    /**
     * End request (consumes leftover bytes).
     *
     * @throws IOException an underlying I/O error occurred
     */
    protected void endRequest() throws IOException {

        if (swallowInput && (lastActiveFilter != -1)) {
            int extraBytes = (int) activeFilters[lastActiveFilter].end();
            byteBuffer.position(byteBuffer.position() - extraBytes);
        }
    }


    // ----------------------------------------------------------- Inner classes

    protected enum HeaderParseStatus {
        DONE, HAVE_MORE_HEADERS, NEED_MORE_DATA
    }


    protected static class HeaderParseData {
        /**
         * The first character of the header line.
         */
        int lineStart = 0;
        /**
         * When parsing header name: first character of the header.<br>
         * When skipping broken header line: first character of the header.<br>
         * When parsing header value: first character after ':'.
         */
        int start = 0;
        /**
         * When parsing header name: not used (stays as 0).<br>
         * When skipping broken header line: not used (stays as 0).<br>
         * When parsing header value: starts as the first character after ':'.
         * Then is increased as far as more bytes of the header are harvested.
         * Bytes from buf[pos] are copied to buf[realPos]. Thus the string from
         * [start] to [realPos-1] is the prepared value of the header, with
         * whitespaces removed as needed.<br>
         */
        int realPos = 0;
        /**
         * When parsing header name: not used (stays as 0).<br>
         * When skipping broken header line: last non-CR/non-LF character.<br>
         * When parsing header value: position after the last not-LWS character.<br>
         */
        int lastSignificantChar = 0;
        /**
         * MB that will store the value of the header. It is null while parsing
         * header name and is created after the name has been parsed.
         */
        MessageBytes headerValue = null;
        public void recycle() {
            lineStart = 0;
            start = 0;
            realPos = 0;
            lastSignificantChar = 0;
            headerValue = null;
        }
    }
}
