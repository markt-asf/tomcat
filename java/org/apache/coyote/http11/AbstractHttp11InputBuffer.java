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

import org.apache.coyote.InputBuffer;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;

/**
 * Abstract base implementation of InputBuffer for HTTP that provides request
 * header parsing as well as transfer encoding.
 */
public abstract class AbstractHttp11InputBuffer implements InputBuffer, ApplicationBufferHandler {

    protected abstract void addFilter(InputFilter inputFilter);

    protected abstract InputFilter[] getFilters();

    protected abstract void addActiveFilter(InputFilter inputFilter);

    protected abstract boolean parseRequestLine(boolean keptAlive, int connectionTimeout, int keepAliveTimeout)
            throws IOException;

    protected abstract int getParsingRequestLinePhase();

    protected abstract boolean parseHeaders() throws IOException;

    protected abstract void nextRequest();

    protected abstract void init(SocketWrapperBase<?> socketWrapper);

    protected abstract void setSwallowInput(boolean b);

    protected abstract void endRequest() throws IOException;

    protected abstract int available(boolean doRead);

    protected abstract boolean isFinished();

    protected abstract boolean isChunking();

    protected abstract ByteBuffer getLeftover();

    protected abstract void recycle();
}
