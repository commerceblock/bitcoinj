/*
 * Copyright 2014 The bitcoinj authors.
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

package org.oceanj.wallet;

import org.oceanj.core.ECKey;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A DecryptingKeyBag filters a pre-existing key bag.
 */
public class DecryptingKeyBag implements KeyBag {
    protected final KeyBag target;

    public DecryptingKeyBag(KeyBag target) {
        this.target = checkNotNull(target);
    }

    @Nullable
    private ECKey maybeDecrypt(ECKey key) {
        if (key == null) {
            return null;
        } else {
            return key;
        }
    }

    private RedeemData maybeDecrypt(RedeemData redeemData) {
        List<ECKey> decryptedKeys = new ArrayList<>();
        for (ECKey key : redeemData.keys) {
            decryptedKeys.add(maybeDecrypt(key));
        }
        return RedeemData.of(decryptedKeys, redeemData.redeemScript);
    }

    @Nullable
    @Override
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        return maybeDecrypt(target.findKeyFromPubHash(pubkeyHash));
    }

    @Nullable
    @Override
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        return maybeDecrypt(target.findKeyFromPubKey(pubkey));
    }

    @Nullable
    @Override
    public RedeemData findRedeemDataFromScriptHash(byte[] scriptHash) {
        return maybeDecrypt(target.findRedeemDataFromScriptHash(scriptHash));
    }
}
