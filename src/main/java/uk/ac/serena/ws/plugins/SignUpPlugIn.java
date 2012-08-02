/*
 * Sign-up plug-in for jWebSocket <http://jwebsocket.org/>.
 *
 * Copyright (C) 2012  Jamie Forth <jamie.forth@eecs.qmul.ac.uk>, 
 * SerenA <http://www.serena.ac.uk>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package uk.ac.serena.ws.plugins;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.jwebsocket.api.PluginConfiguration;
import org.jwebsocket.api.WebSocketConnector;
import org.jwebsocket.api.WebSocketEngine;
import org.jwebsocket.kit.CloseReason;
import org.jwebsocket.kit.PlugInResponse;
import org.jwebsocket.logging.Logging;
import org.jwebsocket.plugins.TokenPlugIn;
import org.jwebsocket.spring.JWebSocketBeanFactory;
import org.jwebsocket.token.Token;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

public class SignUpPlugIn extends TokenPlugIn {
    private static Logger mLog = Logging.getLogger();

    private static ApplicationContext mBeanFactory;
    private JdbcUserDetailsManager userDetailsService;
    private ArrayList<String> defaultGroups;
    private PasswordEncoder passwordEncoder = new StandardPasswordEncoder();

    public SignUpPlugIn(PluginConfiguration aConfiguration) {
        super(aConfiguration);
        if (mLog.isDebugEnabled())
            mLog.debug("Instantiating signup plug-in...");

        // Specify default name space for sample plug-in.
        this.setNamespace(SignUpPlugInConstants.NS_SIGNUP_PLUGIN);

        try {
            mBeanFactory = JWebSocketBeanFactory.getInstance(); // Assume
                                                                // system.xml
                                                                // has been
                                                                // loaded.

            userDetailsService = (JdbcUserDetailsManager) mBeanFactory
                    .getBean("jdbcAuthUserDetailsService");
            defaultGroups = (ArrayList<String>) mBeanFactory.getBean("defaultGroups");

            // give a success message to the administrator
            if (mLog.isInfoEnabled())
                mLog.info("Serena sign-up plug-in successfully instantiated.");

        } catch (Exception lEx) {
            mLog.error(Logging.getSimpleExceptionMessage(lEx, "instantiating sign-up plug-in"));
        }

    }

    @Override
    public void connectorStarted(WebSocketConnector aConnector) {
        // Called every time a client connects to the server.
    }

    @Override
    public void connectorStopped(WebSocketConnector aConnector, CloseReason aCloseReason) {
        // Called every time a client disconnects from the server.
    }

    @Override
    public void engineStarted(WebSocketEngine aEngine) {
        // Called when the engine has started.
        super.engineStarted(aEngine);
    }

    @Override
    public void engineStopped(WebSocketEngine aEngine) {
        // Called when the engine has stopped.
        super.engineStopped(aEngine);
    }

    @Override
    public void processToken(PlugInResponse aResponse, WebSocketConnector aConnector, Token aToken) {

        // This will log the password as plain text.  
        if (mLog.isDebugEnabled())
            mLog.debug("Client '" + aConnector + "' sent Token: '" + aToken.toString() + "'.");

        // Get the type of the token
        String lType = aToken.getType();

        // Get the namespace of the token.
        String lNS = aToken.getNS();

        // Check if token has a type and a matching namespace.
        if (lType != null && lNS != null && lNS.equals(getNamespace())) {
            if (SignUpPlugInConstants.CREATE_USER_ACCOUNT.equals(lType)) {
                createUser(aConnector, aToken);
            }
        }
    }

    public void createUser(WebSocketConnector aConnector, Token aToken) {

        if (mLog.isDebugEnabled())
            mLog.debug("Attempting to create new user.");

        // Create the response token, this includes the unique token-id.
        String username = aToken.getString(SignUpPlugInConstants.USER_NAME);
        String password = aToken.getString(SignUpPlugInConstants.PASSWORD);

        if (username == null) {
            sendErrorToken(aConnector, aToken,
                    SignUpPlugInConstants.ERROR_NO_USERNAME_NOT_PROVIDED,
                    SignUpPlugInConstants.ERROR_MSG_USERNAME_NOT_PROVIDED);
        } else if (password == null) {
            sendErrorToken(aConnector, aToken,
                    SignUpPlugInConstants.ERROR_NO_PASSWORD_NOT_PROVIDED,
                    SignUpPlugInConstants.ERROR_MSG_PASSWORD_NOT_PROVIDED);
        } else if (userDetailsService.userExists(username)) {
            sendErrorToken(aConnector, aToken, SignUpPlugInConstants.ERROR_NO_USERNAME_EXISTS,
                    SignUpPlugInConstants.ERROR_MSG_USERNAME_EXISTS);
        } else {
            // User() requires a list of authorities, which is not
            // actually needed here because we're using groups, which must be
            // manually assigned (below).
            List<GrantedAuthority> authorities = Collections.emptyList();

            // Does salting too.
            String hashedPassword = passwordEncoder.encode(password);

            // Create the new user account.
            User newUser = new User(username, hashedPassword, authorities);
            userDetailsService.createUser(newUser);

            // Assign new user to default groups.
            for (String group : defaultGroups)
                userDetailsService.addUserToGroup(username, group);

            // Send success response token back to the client.
            Token lResponse = createResponse(aToken);
            sendToken(aConnector, aConnector, lResponse);
        }
    }

}
