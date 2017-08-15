package com.gazbert.bxbot.exchanges;

import com.gazbert.bxbot.exchange.api.AuthenticationConfig;
import com.gazbert.bxbot.exchange.api.ExchangeConfig;
import com.gazbert.bxbot.exchange.api.impl.AuthenticationConfigImpl;
import com.gazbert.bxbot.exchange.api.impl.NetworkConfigImpl;
import com.gazbert.bxbot.exchange.api.impl.OtherConfigImpl;
import com.gazbert.bxbot.trading.api.TradingApiException;
import org.easymock.EasyMock;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.easymock.EasyMock.createMock;
import static org.junit.Assert.*;

public class BittrexExchangeAdapterTest {


    @Test
    public void givenValidUrl_whenEncode_thenSecretIsCorrect() throws TradingApiException {
        BittrexExchangeAdapter bittrexAdapter = new BittrexExchangeAdapter();
        ExchangeConfig exchangeConfig = createMock(ExchangeConfig.class);
        AuthenticationConfigImpl auth = new AuthenticationConfigImpl();
        Map<String, String> mapConf = new HashMap<>();
        mapConf.put("key", "xxx");
        mapConf.put("secret", "testest");

        auth.setItems(mapConf);
        EasyMock.expect(exchangeConfig.getAuthenticationConfig()).andReturn(auth);
        NetworkConfigImpl networkConfig = new NetworkConfigImpl();
        networkConfig.setConnectionTimeout(1000);
        EasyMock.expect(exchangeConfig.getNetworkConfig()).andReturn(networkConfig);
        OtherConfigImpl otherConfig = new OtherConfigImpl();
        Map<String, String> otherConfigMap = new HashMap<>();
        otherConfigMap.put("sell-fee", "0.25");
        otherConfigMap.put("buy-fee", "0.20");

        otherConfig.setItems(otherConfigMap);
        EasyMock.expect(exchangeConfig.getOtherConfig()).andReturn(otherConfig);

        EasyMock.replay(exchangeConfig);

        bittrexAdapter.init(exchangeConfig);


        String result = bittrexAdapter.buildURLSignature("test");
        assertEquals("7333d46949b6001c4acf6ebabab423e00acf67e861e0fb3edb3b1b38e02689698d9394b92ab64881cbc6ab641f769cbc8c79a820af9f5694e5d8f225d5e64ff1", result);
    }

}