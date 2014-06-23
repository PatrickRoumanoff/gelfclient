/*
 * Copyright 2014 TORCH GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.graylog2.gelf.client;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.testng.AssertJUnit.*;

public class GelfConfigurationTest {
    private GelfConfiguration config;

    @BeforeMethod
    public void setup() {
        this.config = new GelfConfiguration();
    }

    @Test
    public void testQueueSize() {
        // Check default value.
        assertEquals(512, config.getQueueSize());

        config.setQueueSize(124);

        assertEquals(124, config.getQueueSize());
    }

    @Test
    public void testHost() {
        // Check default value.
        assertEquals("127.0.0.1", config.getHost());

        config.setHost("10.0.0.1");

        assertEquals("10.0.0.1", config.getHost());
    }

    @Test
    public void testPort() {
        // Check default value.
        assertEquals(12201, config.getPort());

        config.setPort(10000);

        assertEquals(10000, config.getPort());
    }

    @Test
    public void testTransport() {
        // Check default value.
        assertEquals(GelfTransports.TCP, config.getTransport());

        // We only have TCP for now so this is pretty useless.
        config.setTransport(GelfTransports.TCP);

        assertEquals(GelfTransports.TCP, config.getTransport());
    }

    @Test
    public void testReconnectDelay() {
        // Check default value.
        assertEquals(500, config.getReconnectDelay());

        config.setReconnectDelay(5000);

        assertEquals(5000, config.getReconnectDelay());
    }

    @Test
    public void testConnectTimeout() {
        // Check default value.
        assertEquals(1000, config.getConnectTimeout());

        config.setConnectTimeout(10000);

        assertEquals(10000, config.getConnectTimeout());
    }

    @Test
    public void testtcpNoDelay() {
        // Check default value.
        assertEquals(false, config.isTcpNoDelay());

        config.setTcpNoDelay(true);

        assertEquals(true, config.isTcpNoDelay());
    }

    @Test
    public void testSendBufferSize() {
        // Check default value.
        assertEquals(-1, config.getSendBufferSize());

        config.setSendBufferSize(32768);

        assertEquals(32768, config.getSendBufferSize());
    }
}