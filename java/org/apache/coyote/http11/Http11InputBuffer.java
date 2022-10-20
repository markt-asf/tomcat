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

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.coyote.CloseNowException;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.HeaderUtil;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.res.StringManager;

/**
 * InputBuffer for HTTP that provides request header parsing as well as transfer
 * encoding.
 */
public class Http11InputBuffer extends AbstractHttp11InputBuffer {

    private static final Log log = LogFactory.getLog(Http11InputBuffer.class);


    /**
     * The string manager for this package.
     */
    private static final StringManager sm = StringManager.getManager(Http11InputBuffer.class);


    /**
     * Parsing state - used for non blocking parsing so that
     * when more data arrives, we can pick up where we left off.
     */
    private volatile boolean parsingRequestLine;
    private boolean parsingRequestLineEol = false;
    private int parsingRequestLineStart = 0;
    private int parsingRequestLineQPos = -1;
    private HeaderParsePosition headerParsePos;


    // ----------------------------------------------------------- Constructors

    public Http11InputBuffer(Request request, int headerBufferSize,
            boolean rejectIllegalHeader, HttpParser httpParser) {

        super(request, headerBufferSize, rejectIllegalHeader, httpParser);

        parsingRequestLine = true;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerParsePos = HeaderParsePosition.HEADER_START;

        inputStreamInputBuffer = new SocketInputBuffer();
    }


    // ------------------------------------------------------- Protected Methods

    @Override
    protected void recycle() {
        super.recycle();

        headerParsePos = HeaderParsePosition.HEADER_START;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        // Recycled last because they are volatile
        // All variables visible to this thread are guaranteed to be visible to
        // any other thread once that thread reads the same volatile. The first
        // action when parsing input data is to read one of these volatiles.
        parsingRequestLine = true;
        parsingHeader = true;
    }


    @Override
    protected void nextRequest() {
        super.nextRequest();

        headerParsePos = HeaderParsePosition.HEADER_START;
        parsingRequestLine = true;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerData.recycle();
    }


    /**
     * Read the request line. This function is meant to be used during the
     * HTTP request header parsing. Do NOT attempt to read the request body
     * using it.
     *
     * @throws IOException If an exception occurs during the underlying socket
     * read operations, or if the given buffer is not big enough to accommodate
     * the whole line.
     *
     * @return true if data is properly fed; false if no data is available
     * immediately and thread should be freed
     */
    @Override
    protected boolean parseRequestLine(boolean keptAlive, int connectionTimeout, int keepAliveTimeout)
            throws IOException {

        // check state
        if (!parsingRequestLine) {
            return true;
        }
        //
        // Skipping blank lines
        //
        if (parsingRequestLinePhase < 2) {
            do {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (keptAlive) {
                        // Haven't read any request data yet so use the keep-alive
                        // timeout.
                        wrapper.setReadTimeout(keepAliveTimeout);
                    }
                    if (!fill(false)) {
                        // A read is pending, so no longer in initial state
                        parsingRequestLinePhase = 1;
                        return false;
                    }
                    // At least one byte of the request has been received.
                    // Switch to the socket timeout.
                    wrapper.setReadTimeout(connectionTimeout);
                }
                if (!keptAlive && byteBuffer.position() == 0 && byteBuffer.limit() >= CLIENT_PREFACE_START.length) {
                    boolean prefaceMatch = true;
                    for (int i = 0; i < CLIENT_PREFACE_START.length && prefaceMatch; i++) {
                        if (CLIENT_PREFACE_START[i] != byteBuffer.get(i)) {
                            prefaceMatch = false;
                        }
                    }
                    if (prefaceMatch) {
                        // HTTP/2 preface matched
                        parsingRequestLinePhase = -1;
                        return false;
                    }
                }
                // Set the start time once we start reading data (even if it is
                // just skipping blank lines)
                if (request.getStartTimeNanos() < 0) {
                    request.setStartTimeNanos(System.nanoTime());
                }
                chr = byteBuffer.get();
            } while ((chr == Constants.CR) || (chr == Constants.LF));
            byteBuffer.position(byteBuffer.position() - 1);

            parsingRequestLineStart = byteBuffer.position();
            parsingRequestLinePhase = 2;
        }
        if (parsingRequestLinePhase == 2) {
            //
            // Reading the method name
            // Method name is a token
            //
            boolean space = false;
            while (!space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                // Spec says method name is a token followed by a single SP but
                // also be tolerant of multiple SP and/or HT.
                int pos = byteBuffer.position();
                chr = byteBuffer.get();
                if (chr == Constants.SP || chr == Constants.HT) {
                    space = true;
                    request.method().setBytes(byteBuffer.array(), parsingRequestLineStart,
                            pos - parsingRequestLineStart);
                } else if (!HttpParser.isToken(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    String invalidMethodValue = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidmethod", invalidMethodValue));
                }
            }
            parsingRequestLinePhase = 3;
        }
        if (parsingRequestLinePhase == 3) {
            // Spec says single SP but also be tolerant of multiple SP and/or HT
            boolean space = true;
            while (space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                chr = byteBuffer.get();
                if (!(chr == Constants.SP || chr == Constants.HT)) {
                    space = false;
                    byteBuffer.position(byteBuffer.position() - 1);
                }
            }
            parsingRequestLineStart = byteBuffer.position();
            parsingRequestLinePhase = 4;
        }
        if (parsingRequestLinePhase == 4) {
            // Mark the current buffer position

            int end = 0;
            //
            // Reading the URI
            //
            boolean space = false;
            while (!space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                int pos = byteBuffer.position();
                prevChr = chr;
                chr = byteBuffer.get();
                if (prevChr == Constants.CR && chr != Constants.LF) {
                    // CR not followed by LF so not an HTTP/0.9 request and
                    // therefore invalid. Trigger error handling.
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    String invalidRequestTarget = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                }
                if (chr == Constants.SP || chr == Constants.HT) {
                    space = true;
                    end = pos;
                } else if (chr == Constants.CR) {
                    // HTTP/0.9 style request. CR is optional. LF is not.
                } else if (chr == Constants.LF) {
                    // HTTP/0.9 style request
                    // Stop this processing loop
                    space = true;
                    // Set blank protocol (indicates HTTP/0.9)
                    request.protocol().setString("");
                    // Skip the protocol processing
                    parsingRequestLinePhase = 7;
                    if (prevChr == Constants.CR) {
                        end = pos - 1;
                    } else {
                        end = pos;
                    }
                } else if (chr == Constants.QUESTION && parsingRequestLineQPos == -1) {
                    parsingRequestLineQPos = pos;
                } else if (parsingRequestLineQPos != -1 && !httpParser.isQueryRelaxed(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    // %nn decoding will be checked at the point of decoding
                    String invalidRequestTarget = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                } else if (httpParser.isNotRequestTargetRelaxed(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    // This is a general check that aims to catch problems early
                    // Detailed checking of each part of the request target will
                    // happen in Http11Processor#prepareRequest()
                    String invalidRequestTarget = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                }
            }
            if (parsingRequestLineQPos >= 0) {
                request.queryString().setBytes(byteBuffer.array(), parsingRequestLineQPos + 1,
                        end - parsingRequestLineQPos - 1);
                request.requestURI().setBytes(byteBuffer.array(), parsingRequestLineStart,
                        parsingRequestLineQPos - parsingRequestLineStart);
            } else {
                request.requestURI().setBytes(byteBuffer.array(), parsingRequestLineStart,
                        end - parsingRequestLineStart);
            }
            // HTTP/0.9 processing jumps to stage 7.
            // Don't want to overwrite that here.
            if (parsingRequestLinePhase == 4) {
                parsingRequestLinePhase = 5;
            }
        }
        if (parsingRequestLinePhase == 5) {
            // Spec says single SP but also be tolerant of multiple and/or HT
            boolean space = true;
            while (space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                byte chr = byteBuffer.get();
                if (!(chr == Constants.SP || chr == Constants.HT)) {
                    space = false;
                    byteBuffer.position(byteBuffer.position() - 1);
                }
            }
            parsingRequestLineStart = byteBuffer.position();
            parsingRequestLinePhase = 6;

            // Mark the current buffer position
            end = 0;
        }
        if (parsingRequestLinePhase == 6) {
            //
            // Reading the protocol
            // Protocol is always "HTTP/" DIGIT "." DIGIT
            //
            while (!parsingRequestLineEol) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }

                int pos = byteBuffer.position();
                prevChr = chr;
                chr = byteBuffer.get();
                if (chr == Constants.CR) {
                    // Possible end of request line. Need LF next else invalid.
                } else if (prevChr == Constants.CR && chr == Constants.LF) {
                    // CRLF is the standard line terminator
                    end = pos - 1;
                    parsingRequestLineEol = true;
                } else if (chr == Constants.LF) {
                    // LF is an optional line terminator
                    end = pos;
                    parsingRequestLineEol = true;
                } else if (prevChr == Constants.CR || !HttpParser.isHttpProtocol(chr)) {
                    String invalidProtocol = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidHttpProtocol", invalidProtocol));
                }
            }

            if ((end - parsingRequestLineStart) > 0) {
                request.protocol().setBytes(byteBuffer.array(), parsingRequestLineStart,
                        end - parsingRequestLineStart);
                parsingRequestLinePhase = 7;
            }
            // If no protocol is found, the ISE below will be triggered.
        }
        if (parsingRequestLinePhase == 7) {
            // Parsing is complete. Return and clean-up.
            parsingRequestLine = false;
            parsingRequestLinePhase = 0;
            parsingRequestLineEol = false;
            parsingRequestLineStart = 0;
            return true;
        }
        throw new IllegalStateException(sm.getString("iib.invalidPhase", Integer.valueOf(parsingRequestLinePhase)));
    }


    /**
     * Available bytes in the buffers for the current request.
     *
     * Note that when requests are pipelined, the data in byteBuffer may relate
     * to the next request rather than this one.
     */
    @Override
    protected int available(boolean read) {
        int available;

        if (lastActiveFilter == -1) {
            available = inputStreamInputBuffer.available();
        } else {
            available = activeFilters[lastActiveFilter].available();
        }

        // Only try a non-blocking read if:
        // - there is no data in the filters
        // - the caller requested a read
        // - there is no data in byteBuffer
        // - the socket wrapper indicates a read is allowed
        //
        // Notes: 1. When pipelined requests are being used available may be
        //        zero even when byteBuffer has data. This is because the data
        //        in byteBuffer is for the next request. We don't want to
        //        attempt a read in this case.
        //        2. wrapper.hasDataToRead() is present to handle the NIO2 case
        try {
            if (available == 0 && read && !byteBuffer.hasRemaining() && wrapper.hasDataToRead()) {
                fill(false);
                available = byteBuffer.remaining();
            }
        } catch (IOException ioe) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("iib.available.readFail"), ioe);
            }
            // Not ideal. This will indicate that data is available which should
            // trigger a read which in turn will trigger another IOException and
            // that one can be thrown.
            available = 1;
        }
        return available;
    }


    // --------------------------------------------------------- Private Methods

    /**
     * Attempts to read some data into the input buffer.
     *
     * @return <code>true</code> if more data was added to the input buffer
     *         otherwise <code>false</code>
     */
    private boolean fill(boolean block) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Before fill(): parsingHeader: [" + parsingHeader +
                    "], parsingRequestLine: [" + parsingRequestLine +
                    "], parsingRequestLinePhase: [" + parsingRequestLinePhase +
                    "], parsingRequestLineStart: [" + parsingRequestLineStart +
                    "], byteBuffer.position(): [" + byteBuffer.position() +
                    "], byteBuffer.limit(): [" + byteBuffer.limit() +
                    "], end: [" + end + "]");
        }

        if (parsingHeader) {
            if (byteBuffer.limit() >= headerBufferSize) {
                if (parsingRequestLine) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                }
                throw new IllegalArgumentException(sm.getString("iib.requestheadertoolarge.error"));
            }
        } else {
            byteBuffer.limit(end).position(end);
        }

        int nRead = -1;
        int mark = byteBuffer.position();
        try {
            if (byteBuffer.position() < byteBuffer.limit()) {
                byteBuffer.position(byteBuffer.limit());
            }
            byteBuffer.limit(byteBuffer.capacity());
            SocketWrapperBase<?> socketWrapper = this.wrapper;
            if (socketWrapper != null) {
                nRead = socketWrapper.read(block, byteBuffer);
            } else {
                throw new CloseNowException(sm.getString("iib.eof.error"));
            }
        } finally {
            // Ensure that the buffer limit and position are returned to a
            // consistent "ready for read" state if an error occurs during in
            // the above code block.
            // Some error conditions can result in the position being reset to
            // zero which also invalidates the mark.
            // https://bz.apache.org/bugzilla/show_bug.cgi?id=65677
            if (byteBuffer.position() >= mark) {
                // // Position and mark are consistent. Assume a read (possibly
                // of zero bytes) has occurred.
                byteBuffer.limit(byteBuffer.position());
                byteBuffer.position(mark);
            } else {
                // Position and mark are inconsistent. Set position and limit to
                // zero so effectively no data is reported as read.
                byteBuffer.position(0);
                byteBuffer.limit(0);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Received ["
                    + new String(byteBuffer.array(), byteBuffer.position(), byteBuffer.remaining(), StandardCharsets.ISO_8859_1) + "]");
        }

        if (nRead > 0) {
            return true;
        } else if (nRead == -1) {
            throw new EOFException(sm.getString("iib.eof.error"));
        } else {
            return false;
        }

    }


    @Override
    protected HeaderParseStatus parseHeader() throws IOException {

        while (headerParsePos == HeaderParsePosition.HEADER_START) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) {
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            prevChr = chr;
            chr = byteBuffer.get();

            if (chr == Constants.CR && prevChr != Constants.CR) {
                // Possible start of CRLF - process the next byte.
            } else if (chr == Constants.LF) {
                // CRLF or LF is an acceptable line terminator
                return HeaderParseStatus.DONE;
            } else {
                if (prevChr == Constants.CR) {
                    // Must have read two bytes (first was CR, second was not LF)
                    byteBuffer.position(byteBuffer.position() - 2);
                } else {
                    // Must have only read one byte
                    byteBuffer.position(byteBuffer.position() - 1);
                }
                break;
            }
        }

        if (headerParsePos == HeaderParsePosition.HEADER_START) {
            // Mark the current buffer position
            headerData.start = byteBuffer.position();
            headerData.lineStart = headerData.start;
            headerParsePos = HeaderParsePosition.HEADER_NAME;
        }

        //
        // Reading the header name
        // Header name is always US-ASCII
        //

        while (headerParsePos == HeaderParsePosition.HEADER_NAME) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) { // parse header
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            int pos = byteBuffer.position();
            chr = byteBuffer.get();
            if (chr == Constants.COLON) {
                headerParsePos = HeaderParsePosition.HEADER_VALUE_START;
                headerData.headerValue = headers.addValue(byteBuffer.array(), headerData.start,
                        pos - headerData.start);
                pos = byteBuffer.position();
                // Mark the current buffer position
                headerData.start = pos;
                headerData.realPos = pos;
                headerData.lastSignificantChar = pos;
                break;
            } else if (!HttpParser.isToken(chr)) {
                // Non-token characters are illegal in header names
                // Parsing continues so the error can be reported in context
                headerData.lastSignificantChar = pos;
                byteBuffer.position(byteBuffer.position() - 1);
                // skipLine() will handle the error
                return skipLine(false);
            }

            // chr is next byte of header name. Convert to lowercase.
            if ((chr >= Constants.A) && (chr <= Constants.Z)) {
                byteBuffer.put(pos, (byte) (chr - Constants.LC_OFFSET));
            }
        }

        // Skip the line and ignore the header
        if (headerParsePos == HeaderParsePosition.HEADER_SKIPLINE) {
            return skipLine(false);
        }

        //
        // Reading the header value (which can be spanned over multiple lines)
        //

        while (headerParsePos == HeaderParsePosition.HEADER_VALUE_START ||
               headerParsePos == HeaderParsePosition.HEADER_VALUE ||
               headerParsePos == HeaderParsePosition.HEADER_MULTI_LINE) {

            if (headerParsePos == HeaderParsePosition.HEADER_VALUE_START) {
                // Skipping spaces
                while (true) {
                    // Read new bytes if needed
                    if (byteBuffer.position() >= byteBuffer.limit()) {
                        if (!fill(false)) {// parse header
                            // HEADER_VALUE_START
                            return HeaderParseStatus.NEED_MORE_DATA;
                        }
                    }

                    chr = byteBuffer.get();
                    if (!(chr == Constants.SP || chr == Constants.HT)) {
                        headerParsePos = HeaderParsePosition.HEADER_VALUE;
                        byteBuffer.position(byteBuffer.position() - 1);
                        // Avoids prevChr = chr at start of header value
                        // parsing which causes problems when chr is CR
                        // (in the case of an empty header value)
                        chr = 0;
                        break;
                    }
                }
            }
            if (headerParsePos == HeaderParsePosition.HEADER_VALUE) {

                // Reading bytes until the end of the line
                boolean eol = false;
                while (!eol) {

                    // Read new bytes if needed
                    if (byteBuffer.position() >= byteBuffer.limit()) {
                        if (!fill(false)) {// parse header
                            // HEADER_VALUE
                            return HeaderParseStatus.NEED_MORE_DATA;
                        }
                    }

                    prevChr = chr;
                    chr = byteBuffer.get();
                    if (chr == Constants.CR && prevChr != Constants.CR) {
                        // CR is only permitted at the start of a CRLF sequence.
                        // Possible start of CRLF - process the next byte.
                    } else if (chr == Constants.LF) {
                        // CRLF or LF is an acceptable line terminator
                        eol = true;
                    } else if (prevChr == Constants.CR) {
                        // Invalid value - also need to delete header
                        return skipLine(true);
                    } else if (chr != Constants.HT && HttpParser.isControl(chr)) {
                        // Invalid value - also need to delete header
                        return skipLine(true);
                    } else if (chr == Constants.SP || chr == Constants.HT) {
                        byteBuffer.put(headerData.realPos, chr);
                        headerData.realPos++;
                    } else {
                        byteBuffer.put(headerData.realPos, chr);
                        headerData.realPos++;
                        headerData.lastSignificantChar = headerData.realPos;
                    }
                }

                // Ignore whitespaces at the end of the line
                headerData.realPos = headerData.lastSignificantChar;

                // Checking the first character of the new line. If the character
                // is a LWS, then it's a multiline header
                headerParsePos = HeaderParsePosition.HEADER_MULTI_LINE;
            }
            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) {// parse header
                    // HEADER_MULTI_LINE
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            byte peek = byteBuffer.get(byteBuffer.position());
            if (headerParsePos == HeaderParsePosition.HEADER_MULTI_LINE) {
                if ((peek != Constants.SP) && (peek != Constants.HT)) {
                    headerParsePos = HeaderParsePosition.HEADER_START;
                    break;
                } else {
                    // Copying one extra space in the buffer (since there must
                    // be at least one space inserted between the lines)
                    byteBuffer.put(headerData.realPos, peek);
                    headerData.realPos++;
                    headerParsePos = HeaderParsePosition.HEADER_VALUE_START;
                }
            }
        }
        // Set the header value
        headerData.headerValue.setBytes(byteBuffer.array(), headerData.start,
                headerData.lastSignificantChar - headerData.start);
        headerData.recycle();
        return HeaderParseStatus.HAVE_MORE_HEADERS;
    }


    private HeaderParseStatus skipLine(boolean deleteHeader) throws IOException {
        boolean rejectThisHeader = rejectIllegalHeader;
        // Check if rejectIllegalHeader is disabled and needs to be overridden
        // for this header. The header name is required to determine if this
        // override is required. The header name is only available once the
        // header has been created. If the header has been created then
        // deleteHeader will be true.
        if (!rejectThisHeader && deleteHeader) {
            if (headers.getName(headers.size() - 1).equalsIgnoreCase("content-length")) {
                // Malformed content-length headers must always be rejected
                // RFC 9112, section 6.3, bullet 5.
                rejectThisHeader = true;
            } else {
                // Only need to delete the header if the request isn't going to
                // be rejected (it will be the most recent one)
                headers.removeHeader(headers.size() - 1);
            }
        }

        // Parse the rest of the invalid header so we can construct a useful
        // exception and/or debug message.
        headerParsePos = HeaderParsePosition.HEADER_SKIPLINE;
        boolean eol = false;

        // Reading bytes until the end of the line
        while (!eol) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) {
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            int pos = byteBuffer.position();
            prevChr = chr;
            chr = byteBuffer.get();
            if (chr == Constants.CR) {
                // Skip
            } else if (chr == Constants.LF) {
                // CRLF or LF is an acceptable line terminator
                eol = true;
            } else {
                headerData.lastSignificantChar = pos;
            }
        }
        if (rejectThisHeader || log.isDebugEnabled()) {
            String message = sm.getString("iib.invalidheader",
                    HeaderUtil.toPrintableString(byteBuffer.array(), headerData.lineStart,
                            headerData.lastSignificantChar - headerData.lineStart + 1));
            if (rejectThisHeader) {
                throw new IllegalArgumentException(message);
            }
            log.debug(message);
        }

        headerParsePos = HeaderParsePosition.HEADER_START;
        return HeaderParseStatus.HAVE_MORE_HEADERS;
    }


    // ----------------------------------------------------------- Inner classes

    private enum HeaderParsePosition {
        /**
         * Start of a new header. A CRLF here means that there are no more
         * headers. Any other character starts a header name.
         */
        HEADER_START,
        /**
         * Reading a header name. All characters of header are HTTP_TOKEN_CHAR.
         * Header name is followed by ':'. No whitespace is allowed.<br>
         * Any non-HTTP_TOKEN_CHAR (this includes any whitespace) encountered
         * before ':' will result in the whole line being ignored.
         */
        HEADER_NAME,
        /**
         * Skipping whitespace before text of header value starts, either on the
         * first line of header value (just after ':') or on subsequent lines
         * when it is known that subsequent line starts with SP or HT.
         */
        HEADER_VALUE_START,
        /**
         * Reading the header value. We are inside the value. Either on the
         * first line or on any subsequent line. We come into this state from
         * HEADER_VALUE_START after the first non-SP/non-HT byte is encountered
         * on the line.
         */
        HEADER_VALUE,
        /**
         * Before reading a new line of a header. Once the next byte is peeked,
         * the state changes without advancing our position. The state becomes
         * either HEADER_VALUE_START (if that first byte is SP or HT), or
         * HEADER_START (otherwise).
         */
        HEADER_MULTI_LINE,
        /**
         * Reading all bytes until the next CRLF. The line is being ignored.
         */
        HEADER_SKIPLINE
    }


    /**
     * This class is an input buffer which will read its data from an input
     * stream.
     */
    private class SocketInputBuffer implements InputBuffer {

        @Override
        public int doRead(ApplicationBufferHandler handler) throws IOException {

            if (byteBuffer.position() >= byteBuffer.limit()) {
                // The application is reading the HTTP request body
                boolean block = (request.getReadListener() == null);
                if (!fill(block)) {
                    if (block) {
                        return -1;
                    } else {
                        return 0;
                    }
                }
            }

            int length = byteBuffer.remaining();
            handler.setByteBuffer(byteBuffer.duplicate());
            byteBuffer.position(byteBuffer.limit());

            return length;
        }

        @Override
        public int available() {
            return byteBuffer.remaining();
        }
    }
}
