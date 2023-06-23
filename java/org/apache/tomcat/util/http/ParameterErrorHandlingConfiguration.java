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
    private boolean skipNoNameParameter = false;
    private boolean skipUrlDecodingError = false;
    private CodingErrorAction malformedInputAction = CodingErrorAction.REPORT;
    private CodingErrorAction unmappableCharacterAction = CodingErrorAction.REPORT;
    private boolean skipDecodingError = false;
    private boolean skipMaxParameterCountError = false;
    private boolean skipRequestBodyTooLarge = false;


    /**
     * If an empty query string parameter is present (@code{...&&...}) is it ignored or is an
     * {@link ParameterEmptyException} thrown?
     *
     * @return {@code true} if the empty parameter is ignored, {@code false} if an exception is thrown
     */
    public boolean getSkipEmptyParameter() {
        return skipEmptyParameter;
    }


    public void setSkipEmptyParameter(boolean skipEmptyParameter) {
        this.skipEmptyParameter = skipEmptyParameter;
    }


    /**
     * If an invalid query string parameter is present (e.g. @code{...&=value&...}) is it ignored or is an
     * {@link ParameterNoNameException} thrown?
     *
     * @return {@code true} if the invalid parameter is ignored, {@code false} if an exception is thrown
     */
    public boolean getSkipNoNameParameter() {
        return skipNoNameParameter;
    }


    public void setSkipNoNameParameter(boolean skipNoNameParameter) {
        this.skipNoNameParameter = skipNoNameParameter;
    }


    /**
     * If an query string parameter contains invalid {@code %nn} encoding (e.g. @code{...&name=va%GGlue&...}) is it
     * ignored or is an {@link ParameterUrlDecodingException} thrown?
     *
     * @return {@code true} if the invalid parameter is ignored, {@code false} if an exception is thrown
     */
    public boolean getSkipUrlDecodingError() {
        return skipUrlDecodingError;
    }


    public void setSkipUrlDecodingError(boolean skipUrlDecodingError) {
        this.skipUrlDecodingError = skipUrlDecodingError;
    }


    /**
     * If an query string parameter contains an invalid byte sequence for the given encoding, how is the invalid byte
     * sequence handled?
     *
     * @return The action to take if an valid byte sequence is found. Note that {@link CodingErrorAction#REPORT} will
     *             trigger an {@link ParameterDecodingException}
     *
     * @see #skipDecodingError
     */
    public CodingErrorAction malformedInputAction() {
        return malformedInputAction;
    }


    public void onMalformedInput(CodingErrorAction action) {
        this.malformedInputAction = action;
    }


    /**
     * If an query string parameter contains a byte sequence representing an unmappable character for the given
     * encoding, how is the byte sequence handled?
     *
     * @return The action to take if an unmappable character is found. Note that {@link CodingErrorAction#REPORT} will
     *             trigger an {@link ParameterDecodingException}
     *
     * @see #skipDecodingError
     */
    public CodingErrorAction unmappableCharacterAction() {
        return unmappableCharacterAction;
    }


    public void onUnmappableCharacter(CodingErrorAction action) {
        this.unmappableCharacterAction = action;
    }


    /**
     * If an query string parameter contains an invalid byte sequence and {@link #onMalformedInput(CodingErrorAction)}
     * or {@link #onUnmappableCharacter(CodingErrorAction)} are configured with {@link CodingErrorAction#REPORT} is the
     * parameter ignore or is an {@link ParameterDecodingException} thrown?
     *
     * @return {@code true} if the invalid parameter is ignored, {@code false} if an exception is thrown
     */
    public boolean getSkipDecodingError() {
        return skipDecodingError;
    }


    public void setSkipDecodingError(boolean skipDecodingError) {
        this.skipDecodingError = skipDecodingError;
    }


    /**
     * If more parameters are found than {@code maxParameterCount} are the parameters above the limit ignored or is an
     * {@link ParameterMaxCountExceededException} thrown?
     *
     * @return {@code true} if the additional parameters are ignored, {@code false} if an exception is thrown
     */
    public boolean getSkipMaxParameterCountError() {
        return skipMaxParameterCountError;
    }


    public void setSkipMaxParameterCountError(boolean skipMaxParameterCountError) {
        this.skipMaxParameterCountError = skipMaxParameterCountError;
    }


    /**
     * When parsing a POST'd request body of type {@code application/x-www-form-urlencoded} for parameters, if the
     * request body is larger than the Connector's {@code maxPostSize} is the request body ignored or is an
     * {@link RequestEntityTooLargeException} thrown? Note that {@code maxSwallowSize} may also affect the processing of
     * the request.
     *
     * @return {@code true} if the request body is ignored, {@code false} if an exception is thrown
     */
    public boolean getSkipRequestBodyTooLarge() {
        return skipRequestBodyTooLarge;
    }


    public void setSkipRequestBodyTooLarge(boolean skipRequestBodyTooLarge) {
        this.skipRequestBodyTooLarge = skipRequestBodyTooLarge;
    }
}
