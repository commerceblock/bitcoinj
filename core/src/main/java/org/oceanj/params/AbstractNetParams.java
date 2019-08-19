/*
 * Copyright 2013 Google Inc.
 * Copyright 2015 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oceanj.params;

import org.oceanj.core.BitcoinSerializer;
import org.oceanj.core.Coin;
import org.oceanj.core.NetworkParameters;
import org.oceanj.core.Transaction;
import org.oceanj.utils.MonetaryFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parameters for Bitcoin-like networks.
 */
public abstract class AbstractNetParams extends NetworkParameters {

    private static final Logger log = LoggerFactory.getLogger(AbstractNetParams.class);

    /**
     * Constructor which defaults to bitcoin uri scheme.
     */
    public AbstractNetParams() {
        super();
    }

    @Override
    public Coin getMaxMoney() {
        return MAX_MONEY;
    }

    @Override
    public Coin getMinNonDustOutput() {
        return Transaction.MIN_NONDUST_OUTPUT;
    }

    @Override
    public MonetaryFormat getMonetaryFormat() {
        return new MonetaryFormat();
    }

    @Override
    public int getProtocolVersionNum(final ProtocolVersion version) {
        return version.getBitcoinProtocolVersion();
    }

    @Override
    public BitcoinSerializer getSerializer(boolean parseRetain) {
        return new BitcoinSerializer(this, parseRetain);
    }

    @Override
    public String getUriScheme() {
        return uriScheme;
    }

    @Override
    public boolean hasMaxMoney() {
        return true;
    }
}
