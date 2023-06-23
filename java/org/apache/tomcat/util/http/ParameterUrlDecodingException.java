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
package org.apache.tomcat.util.http;

/**
 * Extend {@link ParameterInvalidException} to identify the cause as a URL %nn decoding error.
 */
public class ParameterUrlDecodingException extends ParameterInvalidException {

    private static final long serialVersionUID = 1L;


    public ParameterUrlDecodingException(String message, Throwable cause) {
        super(message, cause);
    }


    @Override
    public synchronized Throwable fillInStackTrace() {
        /*
         * This exception is triggered by user input and therefore, since generating stack traces is relatively
         * expensive, stack traces have been disabled for this class. There should be enough information in the
         * exception message to identify the problematic parameter. If not, it is very likely that fixing the message is
         * a better fix than enabling stack traces.
         */
        return this;
    }
}
