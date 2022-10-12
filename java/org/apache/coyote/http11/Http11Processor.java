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

import org.apache.coyote.Adapter;
import org.apache.coyote.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.parser.HttpParser;

public class Http11Processor extends AbstractHttp11Processor {

    private static final Log log = LogFactory.getLog(Http11Processor.class);


    public Http11Processor(AbstractHttp11Protocol<?> protocol, Adapter adapter) {
        super(protocol, adapter);
    }


    @Override
    protected AbstractHttp11InputBuffer createInputBuffer(Request request, AbstractHttp11Protocol<?> protocol,
            HttpParser httpParser) {
        return new Http11InputBuffer(request, protocol.getMaxHttpRequestHeaderSize(),
                protocol.getRejectIllegalHeader(), httpParser);
    }


    @Override
    protected Log getLog() {
        return log;
    }
}
