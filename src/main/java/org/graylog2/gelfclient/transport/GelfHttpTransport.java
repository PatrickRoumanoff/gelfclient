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
package org.graylog2.gelfclient.transport;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.example.http.snoop.HttpSnoopClientHandler;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.graylog2.gelfclient.GelfConfiguration;
import org.graylog2.gelfclient.GelfMessage;
import org.graylog2.gelfclient.encoder.GelfMessageJsonEncoder;
import org.graylog2.gelfclient.encoder.GelfTcpFrameDelimiterEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * A {@link GelfTransport} implementation that uses HTTP to send GELF messages.
 * <p>This class is thread-safe.</p>
 */
public class GelfHttpTransport extends AbstractGelfTransport {
    private static final Logger LOG = LoggerFactory.getLogger(GelfTcpTransport.class);

    /**
     * Creates a new TCP GELF transport.
     *
     * @param config the GELF client configuration
     */
    public GelfHttpTransport(GelfConfiguration config) {
        super(config);
    }

    @Override
    protected void createBootstrap(final EventLoopGroup workerGroup) {
        final Bootstrap bootstrap = new Bootstrap();
        final GelfSenderThread senderThread = new GelfSenderThread(queue, config.getMaxInflightSends());

        bootstrap.group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, config.getConnectTimeout())
                .option(ChannelOption.TCP_NODELAY, config.isTcpNoDelay())
                .option(ChannelOption.SO_KEEPALIVE, config.isTcpKeepAlive())
                .remoteAddress(config.getRemoteAddress())
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        //noinspection Duplicates
                        if (config.isTlsEnabled()) {
                            LOG.debug("TLS enabled.");
                            final SslContext sslContext;
                            //noinspection Duplicates
                            if (!config.isTlsCertVerificationEnabled()) {
                                // If the cert should not be verified just use an insecure trust manager.
                                LOG.debug("TLS certificate verification disabled!");
                                sslContext = SslContext.newClientContext(InsecureTrustManagerFactory.INSTANCE);
                            } else if (config.getTlsTrustCertChainFile() != null) {
                                // If a cert chain file is set, use it.
                                LOG.debug("TLS certificate chain file: {}", config.getTlsTrustCertChainFile());
                                sslContext = SslContext.newClientContext(config.getTlsTrustCertChainFile());
                            } else {
                                // Otherwise use the JVM default cert chain.
                                sslContext = SslContext.newClientContext();
                            }
                            ch.pipeline().addLast(sslContext.newHandler(ch.alloc()));
                        }
                        ch.pipeline().addLast(new HttpClientCodec());
                        ch.pipeline().addLast(new HttpContentDecompressor());
                        ch.pipeline().addLast(new HttpSnoopClientHandler());
                    }
                });

        if (config.getSendBufferSize() != -1) {
            try {
                // Make the connection attempt.
                Channel ch = bootstrap.connect().sync().channel();
                String url = (config.isTlsEnabled() ? "https" : "http") + "://" + config.getHostname() + ":" + config.getPort() + "/gelf";
                // Prepare the HTTP request.
                HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                        HttpMethod.POST,
                        config.);
                if (config.getRemoteAddress().getHostName() != null) {
                    request.headers().set(HttpHeaders.Names.HOST, config.getRemoteAddress().getHostName());
                }
                request.headers().set(HttpHeaders.Names.CONNECTION, HttpHeaders.Values.CLOSE);

                ByteBuf bbuf = Unpooled.copiedBuffer(, StandardCharsets.UTF_8);
                request.headers().set(HttpHeaders.Names.CONTENT_LENGTH, bbuf.readableBytes());
                request.content().clear().writeBytes(bbuf);

                // Send the HTTP request.
                ch.writeAndFlush(request);

                // Wait for the server to close the connection.
                ch.closeFuture().sync();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                // Shut down executor threads to exit.
                workerGroup.shutdownGracefully();
            }

            //noinspection Duplicates
            bootstrap.connect().addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture future) throws Exception {
                    if (future.isSuccess()) {
                        LOG.debug("Connected!");
                    } else {
                        LOG.error("Connection failed: {}", future.cause().getMessage());
                        scheduleReconnect(future.channel().eventLoop());
                    }
                }
            });
        }
    }
