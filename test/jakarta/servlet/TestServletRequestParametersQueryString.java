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
package jakarta.servlet;

import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;

import static org.apache.catalina.startup.SimpleHttpClient.CRLF;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.http.ParameterErrorHandlingConfiguration;

@RunWith(Parameterized.class)
public class TestServletRequestParametersQueryString extends TestServletRequestParametersBase {

    private static final Integer SC_OK = Integer.valueOf(HttpServletResponse.SC_OK);
    private static final Integer SC_BAD_REQUEST = Integer.valueOf(HttpServletResponse.SC_BAD_REQUEST);
    private static final Integer ZERO = Integer.valueOf(0);
    private static final Integer TWO = Integer.valueOf(2);
    private static final Integer THREE = Integer.valueOf(3);

    @Parameterized.Parameters(name = "{index}: queryString[{1}], expectedStatusCode[{2}]")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        ParameterErrorHandlingConfiguration defaultConfig = new ParameterErrorHandlingConfiguration();

        // Empty parameter
        parameterSets.add(new Object[] { defaultConfig, "before=aaa&&after=zzz", SC_BAD_REQUEST, ZERO, null} );
        ParameterErrorHandlingConfiguration config = new ParameterErrorHandlingConfiguration();
        config.setSkipEmptyParameter(true);
        parameterSets.add(new Object[] { config, "before=aaa&&after=zzz", SC_OK, TWO, null} );

        // Invalid parameter
        parameterSets.add(new Object[] { defaultConfig, "before=aaa&=value&after=zzz", SC_BAD_REQUEST, ZERO, null} );
        config = new ParameterErrorHandlingConfiguration();
        config.setSkipNoNameParameter(true);
        parameterSets.add(new Object[] { config, "before=aaa&=value&after=zzz", SC_OK, TWO, null} );

        // Invalid %nn encoding
        parameterSets.add(new Object[] { defaultConfig, "before=aaa&test=val%GGue&after=zzz", SC_BAD_REQUEST, ZERO, null} );
        config = new ParameterErrorHandlingConfiguration();
        config.setSkipUrlDecodingError(true);
        parameterSets.add(new Object[] { config, "before=aaa&test=val%GGue&after=zzz", SC_OK, TWO, null} );

        // Invalid UTF-8 byte
        parameterSets.add(new Object[] { defaultConfig, "before=aaa&test=val%FFue&after=zzz", SC_BAD_REQUEST, ZERO, null} );
        config = new ParameterErrorHandlingConfiguration();
        config.setSkipDecodingError(true);
        config.onMalformedInput(CodingErrorAction.IGNORE);
        parameterSets.add(new Object[] { config, "before=aaa&test=val%FFue&after=zzz", SC_OK, THREE, "value"} );
        config = new ParameterErrorHandlingConfiguration();
        config.setSkipDecodingError(true);
        config.onMalformedInput(CodingErrorAction.REPLACE);
        parameterSets.add(new Object[] { config, "before=aaa&test=val%FFue&after=zzz", SC_OK, THREE, "val\ufffdue"} );
        config = new ParameterErrorHandlingConfiguration();
        config.setSkipDecodingError(true);
        config.onMalformedInput(CodingErrorAction.REPORT);
        parameterSets.add(new Object[] { config, "before=aaa&test=val%FFue&after=zzz", SC_OK, TWO, null} );

        // There are no unmappable UTF-8 code points

        // Too many parameters
        parameterSets.add(new Object[] { defaultConfig, "before=aaa&test=value&after=zzz&extra=yyy", SC_BAD_REQUEST, ZERO, null} );
        config = new ParameterErrorHandlingConfiguration();
        config.setSkipMaxParameterCountError(true);
        parameterSets.add(new Object[] { config, "before=aaa&test=value&after=zzz&extra=yyy", SC_OK, THREE, null} );

        return parameterSets;
    }

    @Parameter(0)
    public ParameterErrorHandlingConfiguration parameterErrorHandlingConfiguration;

    @Parameter(1)
    public String queryString;

    @Parameter(2)
    public int expectedStatusCode;

    @Parameter(3)
    public int expectedValidParameterCount;

    @Parameter(4)
    public String expectedTestParameterValue;


    @Test
    public void testParameterParsing() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        tomcat.getConnector().setMaxParameterCount(3);

        // No file system docBase required
        StandardContext ctx = (StandardContext) tomcat.addContext("", null);

        // Map the test Servlet
        ParameterParsingServlet parameterParsingServlet = new ParameterParsingServlet();
        Tomcat.addServlet(ctx, "parameterParsingServlet", parameterParsingServlet);
        ctx.addServletMappingDecoded("/", "parameterParsingServlet");
        ctx.setParameterErrorHandlingConfiguration(parameterErrorHandlingConfiguration);

        tomcat.start();

        TestParameterClient client = new TestParameterClient();
        client.setPort(getPort());
        client.setRequest(new String[] {
                "GET /?" + queryString +" HTTP/1.1" + CRLF +
                "Host: localhost:" + getPort() + CRLF +
                "Connection: close" + CRLF +
                CRLF });
        client.setResponseBodyEncoding(StandardCharsets.UTF_8);
        client.connect();
        client.processRequest();

        Assert.assertEquals(expectedStatusCode, client.getStatusCode());

        Map<String,List<String>> parameters = parseReportedParameters(client);

        Assert.assertEquals(expectedValidParameterCount, parameters.size());

        if (expectedTestParameterValue != null) {
            List<String> values = parameters.get("test");
            Assert.assertNotNull(values);
            Assert.assertEquals(1,  values.size());
            Assert.assertEquals(expectedTestParameterValue, values.getFirst());
        }
    }
}
