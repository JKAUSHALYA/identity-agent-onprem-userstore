/*
 * Copyright (c) 2017, WSO2 Inc. (http://wso2.com) All Rights Reserved.
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
package org.wso2.carbon.identity.agent.userstore;

import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.TimerTask;

/**
 * HeartBeat task to send ping message to server otherwise connection get lost when idle.
 */
public class HeatBeatTask extends TimerTask {

    private Channel channel;
    private static final Logger LOGGER = LoggerFactory.getLogger(HeatBeatTask.class);

    public HeatBeatTask(Channel channel) {
        this.channel = channel;
    }

    public void run() {
        sendPingToServer();
    }

    /**
     * Send ping message to server.
     */
    private void sendPingToServer() {
        //TODO should send PingWebSocketFrame and it doesn't support at the moment
        ChannelFuture channelFuture = channel.writeAndFlush(new BinaryWebSocketFrame());
        if (LOGGER.isDebugEnabled()) {
            channelFuture.addListener(future -> {
                if (future.isSuccess()) {
                    LOGGER.debug("Successfully pinged to the WSO2 Cloud.");
                } else {
                    LOGGER.debug("Failed to ping to the WSO2 Cloud.");
                }
            });
        }
    }
}
