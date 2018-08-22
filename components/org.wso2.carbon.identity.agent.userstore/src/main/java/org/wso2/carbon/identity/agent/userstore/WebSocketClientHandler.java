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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshaker;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.util.CharsetUtil;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.agent.userstore.constant.CommonConstants;
import org.wso2.carbon.identity.agent.userstore.exception.UserStoreException;
import org.wso2.carbon.identity.agent.userstore.manager.common.UserStoreManager;
import org.wso2.carbon.identity.agent.userstore.manager.common.UserStoreManagerBuilder;
import org.wso2.carbon.identity.agent.userstore.util.UserStoreUtils;
import org.wso2.carbon.identity.user.store.common.MessageRequestUtil;
import org.wso2.carbon.identity.user.store.common.UserStoreConstants;

import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.Timer;
import javax.net.ssl.SSLException;

/**
 * WebSocket Client Handler
 */
public class WebSocketClientHandler extends SimpleChannelInboundHandler<Object> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebSocketClientHandler.class);

    private final WebSocketClientHandshaker handshaker;
    private ChannelPromise handshakeFuture;
    private static final int SOCKET_RETRY_INTERVAL = 5000;

    private String textReceived = "";
    private ByteBuffer bufferReceived = null;
    private WebSocketClient client;
    private Timer time;
    private boolean isDisconnected = false;

    public WebSocketClientHandler(WebSocketClientHandshaker handshaker, WebSocketClient client) {
        this.handshaker = handshaker;
        this.client = client;
    }

    public ChannelFuture handshakeFuture() {
        return handshakeFuture;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        handshakeFuture = ctx.newPromise();
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        handshaker.handshake(ctx.channel());
        scheduleHeatBeatSendTask(ctx.channel());
    }

    /**
     * Schedule a task to send an ping message in every 30 seconds, otherwise connection get lost.
     * @param channel Netty channel
     */
    private void scheduleHeatBeatSendTask(Channel channel) {
        time = new Timer();
        HeatBeatTask heatBeatTask = new HeatBeatTask(channel);
        time.schedule(heatBeatTask, 10 * 1000, 10 * 1000);
    }

    /**
     * Cancel timer task started.
     */
    private void cancelTimer() {
        if (time != null) {
            time.cancel();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        LOGGER.info("Disconnected client connection.");
        isDisconnected = true;
        cancelTimer();
        if (!WebSocketClient.isRetryStarted()) {
            startRetrying();
        }
    }

    private void startRetrying() {
        WebSocketClient.setIsRetryStarted(true);
        while (true) {
            boolean result = false;
            try {
                Thread.sleep(SOCKET_RETRY_INTERVAL);
                LOGGER.info("Trying to reconnect the Identity Cloud...");
                result = client.handhshake();
            } catch (InterruptedException e) {
                LOGGER.error("Error occurred while reconnecting to Identity Cloud", e);
            } catch (URISyntaxException e) {
                LOGGER.error("Error occurred while reconnecting to Identity Cloud", e);
            } catch (SSLException e) {
                LOGGER.error("Error occurred while reconnecting to Identity Cloud", e);
            }
            if (result) {
                isDisconnected = false;
                WebSocketClient.setIsRetryStarted(false);
                LOGGER.info("Agent successfully reconnected to Identity Cloud.");
                break;
            }
        }
    }

    /**
     * Write response to server socket with correlationId
     * @param channel netty channel
     * @param correlationId id to correlationId request response
     * @param result user operation result
     */
    private void writeResponse(Channel channel, String correlationId, String result) {
        channel.writeAndFlush(
                new TextWebSocketFrame(MessageRequestUtil.getUserResponseJSONMessage(correlationId, result)));
    }

    /**
     * Process authentication request
     * @param channel netty channel
     * @param requestObj json request data object
     * @throws UserStoreException
     */
    private void processAuthenticationRequest(Channel channel, JSONObject requestObj) throws UserStoreException {

        JSONObject requestData = requestObj.getJSONObject(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA);
        UserStoreManager userStoreManager = UserStoreManagerBuilder.getUserStoreManager();

        String username = requestData.getString(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_USER_NAME);
        username = UserStoreUtils.getUserStoreAwareUsername(username);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Starting to authenticate user " + username);
        }

        boolean isAuthenticated = userStoreManager.doAuthenticate(
                username,
                requestData.getString(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_USER_PASSWORD));
        String authenticationResult = UserAgentConstants.UM_OPERATION_AUTHENTICATE_RESULT_FAIL;

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Authentication completed. User: " + username + " result: " + isAuthenticated);
        }
        if (isAuthenticated) {
            authenticationResult = UserAgentConstants.UM_OPERATION_AUTHENTICATE_RESULT_SUCCESS;
        }
        writeResponse(channel, (String) requestObj.get(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA_CORRELATION_ID),
                authenticationResult);
    }

    /**
     * Process Get claims request
     * @param channel netty channel
     * @param requestObj json request data object
     * @throws UserStoreException
     */
    private void processGetClaimsRequest(Channel channel, JSONObject requestObj) throws UserStoreException {

        JSONObject requestData = requestObj.getJSONObject(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA);

        String username = (String) requestData.get(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_USER_NAME);
        username = UserStoreUtils.getUserStoreAwareUsername(username);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Starting to get claims for user: " + username);
        }

        String claims = (String) requestData.get(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_CLAIMS);
        String[] claimArray = claims.split(CommonConstants.ATTRIBUTE_LIST_SEPERATOR);
        UserStoreManager userStoreManager = UserStoreManagerBuilder.getUserStoreManager();

        Map<String, String> propertyMap = userStoreManager.getUserClaimValues(username, claimArray);
        JSONObject returnObject = new JSONObject(propertyMap);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Claims retrieval completed. User: " + username + " claims: " + propertyMap
                    .toString());
        }
        writeResponse(channel, (String) requestObj.get(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA_CORRELATION_ID),
                returnObject.toString());
    }

    /**
     * Process get user roles request
     * @param channel netty channel
     * @param requestObj json request data object
     * @throws UserStoreException
     */
    private void processGetUserRolesRequest(Channel channel, JSONObject requestObj) throws UserStoreException {
        JSONObject requestData = requestObj.getJSONObject(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA);

        String username = (String) requestData.get(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_USER_NAME);
        username = UserStoreUtils.getUserStoreAwareUsername(username);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Starting to get user roles for user: " + username);
        }

        UserStoreManager userStoreManager = UserStoreManagerBuilder.getUserStoreManager();
        String[] roles = userStoreManager.doGetExternalRoleListOfUser(username);
        JSONObject jsonObject = new JSONObject();
        JSONArray usernameArray = new JSONArray(roles);
        jsonObject.put("groups", usernameArray);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("User roles retrieval completed. User: " + username + " roles: " + Arrays.toString(
                    roles));
        }
        writeResponse(channel, (String) requestObj.get(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA_CORRELATION_ID),
                jsonObject.toString());
    }

    /**
     * Process get roles request
     * @param channel netty channel
     * @param requestObj json request data object
     * @throws UserStoreException
     */
    private void processGetRolesRequest(Channel channel, JSONObject requestObj) throws UserStoreException {
        JSONObject requestData = requestObj.getJSONObject(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Starting to get roles.");
        }
        int limit = requestData.getInt(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_GET_ROLE_LIMIT);

        if (limit == 0) {
            limit = CommonConstants.MAX_USER_LIST;
        }
        UserStoreManager userStoreManager = UserStoreManagerBuilder.getUserStoreManager();
        String[] roleNames = userStoreManager.doGetRoleNames("*", limit);
        JSONObject returnObject = new JSONObject();
        JSONArray rolesArray = new JSONArray(roleNames);
        returnObject.put("groups", rolesArray);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Roles retrieval completed.");
        }
        writeResponse(channel, (String) requestObj.get(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA_CORRELATION_ID),
                returnObject.toString());
    }

    /**
     * Process get roles request
     * @param channel netty channel
     * @param requestObj json request data object
     * @throws UserStoreException
     */
    private void processGetUsersListRequest(Channel channel, JSONObject requestObj) throws UserStoreException {
        JSONObject requestData = requestObj.getJSONObject(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Starting to get users");
        }

        int limit = requestData.getInt(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_GET_USER_LIMIT);
        String filter = (String) requestData.get(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_GET_USER_FILTER);

        if (limit == 0) {
            limit = CommonConstants.MAX_USER_LIST;
        }
        UserStoreManager userStoreManager = UserStoreManagerBuilder.getUserStoreManager();
        String[] roleNames = userStoreManager.doListUsers(filter, limit);
        JSONObject returnObject = new JSONObject();
        JSONArray usernameArray = new JSONArray(roleNames);
        returnObject.put("usernames", usernameArray);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Users list retrieval completed.");
        }
        writeResponse(channel, (String) requestObj.get(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA_CORRELATION_ID),
                returnObject.toString());
    }

    /**
     * Process user operation request
     * @param channel netty channel
     * @param requestObj json request data object
     * @throws UserStoreException
     */
    private void processUserOperationRequest(Channel channel, JSONObject requestObj) throws UserStoreException {

        String type = (String) requestObj.get(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA_TYPE);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Message receive for operation " + type);
        }
        switch (type) {
        case UserStoreConstants.UM_OPERATION_TYPE_AUTHENTICATE:
            processAuthenticationRequest(channel, requestObj);
            break;
        case UserStoreConstants.UM_OPERATION_TYPE_GET_CLAIMS:
            processGetClaimsRequest(channel, requestObj);
            break;
        case UserStoreConstants.UM_OPERATION_TYPE_GET_USER_ROLES:
            processGetUserRolesRequest(channel, requestObj);
            break;
        case UserStoreConstants.UM_OPERATION_TYPE_GET_ROLES:
            processGetRolesRequest(channel, requestObj);
            break;
        case UserStoreConstants.UM_OPERATION_TYPE_GET_USER_LIST:
            processGetUsersListRequest(channel, requestObj);
            break;
        case UserStoreConstants.UM_OPERATION_TYPE_ERROR:
            logError(requestObj);
            if (!isDisconnected) {
                client.setShutdownFlag(true);
                System.exit(0);
            }
            break;
        default:
            LOGGER.error("Invalid user operation request type : " + type + " received.");
            break;
        }
    }

    private void logError(JSONObject requestObj) {
        JSONObject requestData = (JSONObject) requestObj.get(UserStoreConstants.UM_JSON_ELEMENT_REQUEST_DATA);
        String message = (String) requestData.get(UserAgentConstants.UM_JSON_ELEMENT_REQUEST_DATA_MESSAGE);
        LOGGER.error(message);
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
        Channel ch = ctx.channel();
        if (!handshaker.isHandshakeComplete()) {
            handshaker.finishHandshake(ch, (FullHttpResponse) msg);
            handshakeFuture.setSuccess();
            return;
        }

        if (msg instanceof FullHttpResponse) {
            FullHttpResponse response = (FullHttpResponse) msg;
            throw new IllegalStateException(
                    "Unexpected FullHttpResponse (getStatus=" + response.status() +
                            ", content=" + response.content().toString(CharsetUtil.UTF_8) + ')');
        }

        WebSocketFrame frame = (WebSocketFrame) msg;
        if (frame instanceof TextWebSocketFrame) {
            TextWebSocketFrame textFrame = (TextWebSocketFrame) frame;
            JSONObject requestObj = new JSONObject(textFrame.text());
            textReceived = textFrame.text();
            processUserOperationRequest(ch, requestObj);
        } else if (frame instanceof BinaryWebSocketFrame) {
            BinaryWebSocketFrame binaryFrame = (BinaryWebSocketFrame) frame;
            bufferReceived = binaryFrame.content().nioBuffer();
            LOGGER.info("WebSocket Client received  binary message: " + bufferReceived.toString());
        } else if (frame instanceof PongWebSocketFrame) {
            LOGGER.info("WebSocket Client received pong.");
            PongWebSocketFrame pongFrame = (PongWebSocketFrame) frame;
            bufferReceived = pongFrame.content().nioBuffer();
        } else if (frame instanceof CloseWebSocketFrame) {
            LOGGER.info("WebSocket Client received closing.");
            ch.close();
        }
    }

    /**
     * @return the text received from the server.
     */
    public String getTextReceived() {
        return textReceived;
    }

    /**
     * @return the binary data received from the server.
     */
    public ByteBuffer getBufferReceived() {
        return bufferReceived;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (!handshakeFuture.isDone()) {
            LOGGER.error("Handshake failed : " + cause.getMessage(), cause);
            handshakeFuture.setFailure(cause);
        }
        ctx.close();
    }
}

