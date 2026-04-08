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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class HeaderUtil {

    /**
     * The set of trailer field names that MUST NOT be included in trailer fields as per RFC 9110 section 6.5.1.
     */
    public static final Set<String> DISALLOWED_TRAILER_FIELD_NAMES;

    static {
        // Always add these in lower case
        Set<String> names = new HashSet<>();
        names.add("age");
        names.add("cache-control");
        names.add("content-length");
        names.add("content-encoding");
        names.add("content-range");
        names.add("content-type");
        names.add("date");
        names.add("expires");
        names.add("location");
        names.add("retry-after");
        names.add("trailer");
        names.add("transfer-encoding");
        names.add("vary");
        names.add("warning");
        DISALLOWED_TRAILER_FIELD_NAMES = Collections.unmodifiableSet(names);
    }

    /**
     * Converts an HTTP header line in byte form to a printable String. Bytes corresponding to visible ASCII characters
     * will be converted to those characters. All other bytes (0x00 to 0x1F, 0x7F to 0xFF) will be represented in 0xNN
     * form.
     *
     * @param bytes  Contains an HTTP header line
     * @param offset The start position of the header line in the array
     * @param len    The length of the HTTP header line
     *
     * @return A String with non-printing characters replaced by the 0xNN equivalent
     */
    public static String toPrintableString(byte[] bytes, int offset, int len) {
        StringBuilder result = new StringBuilder();
        for (int i = offset; i < offset + len; i++) {
            char c = (char) (bytes[i] & 0xFF);
            if (c < 0x20 || c > 0x7E) {
                result.append("0x");
                result.append(Character.forDigit((c >> 4) & 0xF, 16));
                result.append(Character.forDigit((c) & 0xF, 16));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }


    /*
     * Filters out CTLs excluding TAB and any code points above 255 (since this is meant to be ISO-8859-1).
     *
     * This doesn't perform full HTTP validation. For example, it does not limit field names to tokens.
     *
     * Strictly, correct trailer fields is an application concern. The filtering here is a basic attempt to help
     * mis-behaving applications prevent the worst of the potential side-effects of invalid trailer fields.
     */
    public static String filterForHeaders(String input) {
        char[] chars = input.toCharArray();
        boolean updated = false;
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] < 32 && chars[i] != 9 || chars[i] == 127 || chars[i] > 255) {
                chars[i] = ' ';
                updated = true;
            }
        }

        if (updated) {
            return new String(chars);
        } else {
            return input;
        }
    }


    private HeaderUtil() {
        // Utility class. Hide default constructor.
    }
}
