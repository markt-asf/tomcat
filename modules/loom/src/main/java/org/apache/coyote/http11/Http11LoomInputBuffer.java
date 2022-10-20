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
 * Loom optimised InputBuffer for HTTP that provides request header parsing as
 * well as transfer encoding.
 */
public class Http11LoomInputBuffer extends AbstractHttp11InputBuffer {

    private static final Log log = LogFactory.getLog(Http11LoomInputBuffer.class);


    /**
     * The string manager for this package.
     */
    private static final StringManager sm = StringManager.getManager(Http11LoomInputBuffer.class);


    // ----------------------------------------------------------- Constructors

    public Http11LoomInputBuffer(Request request, int headerBufferSize,
            boolean rejectIllegalHeader, HttpParser httpParser) {

        super(request, headerBufferSize, rejectIllegalHeader, httpParser);

        inputStreamInputBuffer = new SocketInputBuffer();
    }


    // ------------------------------------------------------- Protected Methods

    @Override
    protected void recycle() {
        super.recycle();
        // Recycled separately because other implementations need to control the
        // timing of recycling the volatiles.
        parsingHeader = true;
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
     * @return always {@code true}
     */
    @Override
    protected boolean parseRequestLine(boolean keptAlive, int connectionTimeout, int keepAliveTimeout)
            throws IOException {

        try {
            parsingRequestLinePhase = 0;

            // Skipping blank lines
            do {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (keptAlive) {
                        // Haven't read any request data yet so use the keep-alive
                        // timeout.
                        wrapper.setReadTimeout(keepAliveTimeout);
                    }
                    fill();
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

            // Reading the method name. Method name is a token.
            int methodStartPos = byteBuffer.position();
            boolean space = false;
            while (!space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    fill();
                }
                // Spec says method name is a token followed by a single SP but
                // also be tolerant of multiple SP and/or HT.
                int pos = byteBuffer.position();
                chr = byteBuffer.get();
                if (chr == Constants.SP || chr == Constants.HT) {
                    space = true;
                    request.method().setBytes(byteBuffer.array(), methodStartPos, pos - methodStartPos);
                } else if (!HttpParser.isToken(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    String invalidMethodValue = parseInvalid(methodStartPos, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidmethod", invalidMethodValue));
                }
            }

            // Spec says single SP but also be tolerant of multiple SP and/or HT
            while (space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    fill();
                }
                chr = byteBuffer.get();
                if (!(chr == Constants.SP || chr == Constants.HT)) {
                    space = false;
                    byteBuffer.position(byteBuffer.position() - 1);
                }
            }

            // Reading the URI
            boolean http09 = false;
            int uriStartPos = byteBuffer.position();
            int uriEndPos = -1;
            int parsingRequestLineQPos = -1;
            while (!space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    fill();
                }
                int pos = byteBuffer.position();
                prevChr = chr;
                chr = byteBuffer.get();
                if (prevChr == Constants.CR && chr != Constants.LF) {
                    // CR not followed by LF so not an HTTP/0.9 request and
                    // therefore invalid. Trigger error handling.
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    String invalidRequestTarget = parseInvalid(uriStartPos, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                }
                if (chr == Constants.SP || chr == Constants.HT) {
                    space = true;
                    uriEndPos = pos;
                } else if (chr == Constants.CR) {
                    // HTTP/0.9 style request. CR is optional. LF is not.
                } else if (chr == Constants.LF) {
                    // HTTP/0.9 style request
                    // Stop this processing loop
                    space = true;
                    // Set blank protocol (indicates HTTP/0.9)
                    request.protocol().setString("");
                    http09 = true;
                    if (prevChr == Constants.CR) {
                        uriEndPos = pos - 1;
                    } else {
                        uriEndPos = pos;
                    }
                } else if (chr == Constants.QUESTION && parsingRequestLineQPos == -1) {
                    parsingRequestLineQPos = pos;
                } else if (parsingRequestLineQPos != -1 && !httpParser.isQueryRelaxed(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    // %nn decoding will be checked at the point of decoding
                    String invalidRequestTarget = parseInvalid(uriStartPos, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                } else if (httpParser.isNotRequestTargetRelaxed(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    // This is a general check that aims to catch problems early
                    // Detailed checking of each part of the request target will
                    // happen in Http11Processor#prepareRequest()
                    String invalidRequestTarget = parseInvalid(uriStartPos, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                }
            }
            if (parsingRequestLineQPos >= 0) {
                request.queryString().setBytes(byteBuffer.array(), parsingRequestLineQPos + 1,
                        uriEndPos - parsingRequestLineQPos - 1);
                request.requestURI().setBytes(byteBuffer.array(), uriStartPos,
                        parsingRequestLineQPos - uriStartPos);
            } else {
                request.requestURI().setBytes(byteBuffer.array(), uriStartPos,
                        uriEndPos - uriStartPos);
            }

            if (!http09) {
                // Spec says single SP but also be tolerant of multiple and/or HT
                while (space) {
                    // Read new bytes if needed
                    if (byteBuffer.position() >= byteBuffer.limit()) {
                        fill();
                    }
                    byte chr = byteBuffer.get();
                    if (!(chr == Constants.SP || chr == Constants.HT)) {
                        space = false;
                        byteBuffer.position(byteBuffer.position() - 1);
                    }
                }

                // Reading the protocol. Protocol is always "HTTP/" DIGIT "." DIGIT
                int protocolStartPos = byteBuffer.position();
                int protocolEndPos = -1;
                boolean parsingRequestLineEol = false;
                while (!parsingRequestLineEol) {
                    // Read new bytes if needed
                    if (byteBuffer.position() >= byteBuffer.limit()) {
                        fill();
                    }

                    int pos = byteBuffer.position();
                    prevChr = chr;
                    chr = byteBuffer.get();
                    if (chr == Constants.CR) {
                        // Possible end of request line. Need LF next else invalid.
                    } else if (prevChr == Constants.CR && chr == Constants.LF) {
                        // CRLF is the standard line terminator
                        protocolEndPos = pos - 1;
                        parsingRequestLineEol = true;
                    } else if (chr == Constants.LF) {
                        // LF is an optional line terminator
                        protocolEndPos = pos;
                        parsingRequestLineEol = true;
                    } else if (prevChr == Constants.CR || !HttpParser.isHttpProtocol(chr)) {
                        String invalidProtocol = parseInvalid(protocolStartPos, byteBuffer);
                        throw new IllegalArgumentException(sm.getString("iib.invalidHttpProtocol", invalidProtocol));
                    }
                }

                if ((protocolEndPos - protocolStartPos) > 0) {
                    request.protocol().setBytes(byteBuffer.array(), protocolStartPos,
                            protocolEndPos - protocolStartPos);
                }
                // If no protocol is found, the ISE below will be triggered.
            }

            // Parsing is complete. Return and clean-up.
            return true;
        } catch (IllegalArgumentException iae) {
            // Avoid unknown protocol triggering an additional error
            request.protocol().setString(Constants.HTTP_11);

            throw iae;
        }
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
                // TODO: Review this for Loom
                fill();
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
     * Performs a blocking read to add some data into the input buffer.
     */
    private void fill() throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Before fill(): parsingHeader: [" + parsingHeader +
                    "], byteBuffer.position(): [" + byteBuffer.position() +
                    "], byteBuffer.limit(): [" + byteBuffer.limit() +
                    "], end: [" + end + "]");
        }

        if (parsingHeader) {
            if (byteBuffer.limit() >= headerBufferSize) {
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
                nRead = socketWrapper.read(true, byteBuffer);
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

        if (nRead == -1) {
            throw new EOFException(sm.getString("iib.eof.error"));
        }
    }


    @Override
    protected HeaderParseStatus parseHeader() throws IOException {

        while (true) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                fill();
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

        // Mark the current buffer position
        headerData.start = byteBuffer.position();
        headerData.lineStart = headerData.start;

        // Reading the header name
        // Header name is always US-ASCII
        while (true) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                fill();
            }

            int pos = byteBuffer.position();
            chr = byteBuffer.get();
            if (chr == Constants.COLON) {
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

        //
        // Reading the header value (which can be spanned over multiple lines)
        //
        while (true) {

            // Skipping spaces
            while (true) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    fill();
                }

                chr = byteBuffer.get();
                if (!(chr == Constants.SP || chr == Constants.HT)) {
                    byteBuffer.position(byteBuffer.position() - 1);
                    // Avoids prevChr = chr at start of header value
                    // parsing which causes problems when chr is CR
                    // (in the case of an empty header value)
                    chr = 0;
                    break;
                }
            }

            // Reading bytes until the end of the line
            boolean eol = false;
            while (!eol) {

                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    fill();
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

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                fill();
            }

            byte peek = byteBuffer.get(byteBuffer.position());
            if ((peek != Constants.SP) && (peek != Constants.HT)) {
                break;
            } else {
                // Copying one extra space in the buffer (since there must
                // be at least one space inserted between the lines)
                byteBuffer.put(headerData.realPos, peek);
                headerData.realPos++;
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
        boolean eol = false;

        // Reading bytes until the end of the line
        while (!eol) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                fill();
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

        return HeaderParseStatus.HAVE_MORE_HEADERS;
    }


    // ----------------------------------------------------------- Inner classes

    /**
     * This class is an input buffer which will read its data from an input
     * stream.
     */
    private class SocketInputBuffer implements InputBuffer {

        @Override
        public int doRead(ApplicationBufferHandler handler) throws IOException {

            if (byteBuffer.position() >= byteBuffer.limit()) {
                fill();
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
