/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.http;

import java.nio.charset.CodingErrorAction;

public class ParameterErrorHandlingConfiguration {

    private boolean skipEmptyParameter = false;
    private boolean skipInvalidParameter = false;
    private boolean skipUrlDecodingError = false;
    private CodingErrorAction malformedInputAction = CodingErrorAction.REPORT;
    private CodingErrorAction unmappableCharacterAction = CodingErrorAction.REPORT;
    private boolean skipDecodingError = false;
    private boolean skipMaxParameterCountError = false;


    public boolean getSkipEmptyParameter() {
        return skipEmptyParameter;
    }


    public void setSkipEmptyParameter(boolean skipEmptyParameter) {
        this.skipEmptyParameter = skipEmptyParameter;
    }


    public boolean getSkipInvalidParameter() {
        return skipInvalidParameter;
    }


    public void setSkipInvalidParameter(boolean skipInvalidParameter) {
        this.skipInvalidParameter = skipInvalidParameter;
    }


    public boolean getSkipUrlDecodingError() {
        return skipUrlDecodingError;
    }


    public void setSkipUrlDecodingError(boolean skipUrlDecodingError) {
        this.skipUrlDecodingError = skipUrlDecodingError;
    }


    public CodingErrorAction malformedInputAction() {
        return malformedInputAction;
    }


    public void onMalformedInput(CodingErrorAction action) {
        this.malformedInputAction = action;
    }


    public CodingErrorAction unmappableCharacterAction() {
        return unmappableCharacterAction;
    }


    public void onUnmappableCharacter(CodingErrorAction action) {
        this.unmappableCharacterAction = action;
    }


    public boolean getSkipDecodingError() {
        return skipDecodingError;
    }


    public void setSkipDecodingError(boolean skipDecodingError) {
        this.skipDecodingError = skipDecodingError;
    }


    public boolean getSkipMaxParameterCountError() {
        return skipMaxParameterCountError;
    }


    public void setSkipMaxParameterCountError(boolean skipMaxParameterCountError) {
        this.skipMaxParameterCountError = skipMaxParameterCountError;
    }
}
