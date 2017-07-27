/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Gareth Jon Lynch
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.gazbert.bxbot.rest.api.exchange;

import com.google.common.base.MoreObjects;

import java.util.ArrayList;
import java.util.List;

/**
 * Domain object representing the Exchange Adapter Network config.
 *
 * @author gazbert
 */
public class NetworkConfig {

    private Integer connectionTimeout;
    private List<Integer> nonFatalErrorHttpStatusCodes;
    private List<String> nonFatalErrorMessages;

//    public nonFatalErrorHttpStatusCodes: ErrorCode[],
//    public nonFatalErrorMessages: ErrorMessage[]) {

    public NetworkConfig() {
        nonFatalErrorHttpStatusCodes = new ArrayList<>();
        nonFatalErrorMessages = new ArrayList<>();
    }

    public Integer getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(Integer connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    public List<Integer> getNonFatalErrorHttpStatusCodes() {
        return nonFatalErrorHttpStatusCodes;
    }

    public void setNonFatalErrorHttpStatusCodes(List<Integer> nonFatalErrorHttpStatusCodes) {
        this.nonFatalErrorHttpStatusCodes = nonFatalErrorHttpStatusCodes;
    }

    public List<String> getNonFatalErrorMessages() {
        return nonFatalErrorMessages;
    }

    public void setNonFatalErrorMessages(List<String> nonFatalErrorMessages) {
        this.nonFatalErrorMessages = nonFatalErrorMessages;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("connectionTimeout", connectionTimeout)
                .add("nonFatalErrorHttpStatusCodes", nonFatalErrorHttpStatusCodes)
                .add("nonFatalErrorMessages", nonFatalErrorMessages)
                .toString();
    }
}