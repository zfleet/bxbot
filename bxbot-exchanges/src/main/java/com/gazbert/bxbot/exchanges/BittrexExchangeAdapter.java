package com.gazbert.bxbot.exchanges;

import com.gazbert.bxbot.exchange.api.AuthenticationConfig;
import com.gazbert.bxbot.exchange.api.ExchangeAdapter;
import com.gazbert.bxbot.exchange.api.ExchangeConfig;
import com.gazbert.bxbot.exchange.api.OtherConfig;
import com.gazbert.bxbot.trading.api.*;
import com.google.common.base.MoreObjects;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class BittrexExchangeAdapter  extends AbstractExchangeAdapter implements ExchangeAdapter {
    private static final Logger LOG = LogManager.getLogger();

    /**
     * The base URI for all Bittrex API calls.
     */
    private static final String BITTREX_BASE_URI = "https://bittrex.com/api/";

    /**
     * The version of the Bittrex API being used.
     */
    private static final String BITTREX_API_VERSION = "v1.1";

    /**
     * The public API path part of the Bittrex base URI.
     */
    private static final String BITTREX_PUBLIC_PATH = "/public/";

    /**
     * The Account API path part of the Bittrex base URI.
     */
    private static final String BITTREX_ACCOUNT_PATH = "/account/";

    /**
     * The private API path part of the Kraken base URI.
     */
    private static final String BITTREX_MARKET_PATH = "/market/";

    /**
     * The public API URI.
     */
    private static final String PUBLIC_API_BASE_URL = BITTREX_BASE_URI + BITTREX_API_VERSION + BITTREX_PUBLIC_PATH;

    /**
     * The account API URI (must be authenticated).
     */
    private static final String ACCOUNT_API_BASE_URL = BITTREX_BASE_URI + BITTREX_API_VERSION + BITTREX_ACCOUNT_PATH;

    /**
     * The market API URI (must be authenticated).
     */
    private static final String MARKET_API_BASE_URL = BITTREX_BASE_URI + BITTREX_API_VERSION + BITTREX_MARKET_PATH;

    /**
     * Used for reporting unexpected errors.
     */
    private static final String UNEXPECTED_ERROR_MSG = "Unexpected error has occurred in Bittrex Exchange Adapter. ";

    /**
     * Unexpected IO error message for logging.
     */
    private static final String UNEXPECTED_IO_ERROR_MSG = "Failed to connect to Exchange due to unexpected IO error.";

    /**
     * Error message for when API call to get Market Orders fails.
     */
    private static final String FAILED_TO_GET_MARKET_ORDERS = "Failed to get Market Order Book from exchange. Details: ";

    /**
     * Error message for when API call to get Balance fails.
     */
    private static final String FAILED_TO_GET_BALANCE = "Failed to get Balance from exchange. Details: ";

    /**
     * Error message for when API call to get Ticker fails.
     */
    private static final String FAILED_TO_GET_TICKER = "Failed to get Ticker from exchange. Details: ";

    /**
     * Error message for when API call to get Open Orders fails.
     */
    private static final String FAILED_TO_GET_OPEN_ORDERS = "Failed to get Open Orders from exchange. Details: ";

    /**
     * Error message for when API call to Add Order fails.
     */
    private static final String FAILED_TO_ADD_ORDER = "Failed to Add Order on exchange. Details: ";

    /**
     * Error message for when API call to Cancel Order fails.
     */
    private static final String FAILED_TO_CANCEL_ORDER = "Failed to Cancel Order on exchange. Details: ";

    /**
     * Name of PUBLIC key prop in config file.
     */
    private static final String KEY_PROPERTY_NAME = "key";

    /**
     * Name of secret prop in config file.
     */
    private static final String SECRET_PROPERTY_NAME = "secret";

    /**
     * Name of buy fee property in config file.
     */
    private static final String BUY_FEE_PROPERTY_NAME = "buy-fee";

    /**
     * Name of sell fee property in config file.
     */
    private static final String SELL_FEE_PROPERTY_NAME = "sell-fee";

    private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS";
    private static final String DATE_FORMAT_NO_MILLIS = "yyyy-MM-dd'T'HH:mm:ss";

    private static final SimpleDateFormat DATE_PARSER = new SimpleDateFormat(DATE_FORMAT);
    private static final SimpleDateFormat DATE_PARSER_NO_MILLIS = new SimpleDateFormat(DATE_FORMAT_NO_MILLIS);

    private static final TimeZone TIME_ZONE = TimeZone.getTimeZone("UTC");


    /**
     * Nonce used for sending authenticated messages to the exchange.
     */
    private static long nonce = 0;

    /**
     * Exchange buy fees in % in {@link BigDecimal} format.
     */
    private BigDecimal buyFeePercentage;

    /**
     * Exchange sell fees in % in {@link BigDecimal} format.
     */
    private BigDecimal sellFeePercentage;

    /**
     * Used to indicate if we have initialised the MAC authentication protocol.
     */
    private boolean initializedMACAuthentication = false;

    /**
     * The key used in the MAC message.
     */
    private String key = "";

    /**
     * The secret used for signing MAC message.
     */
    private String secret = "";

    /**
     * Provides the "Message Authentication Code" (MAC) algorithm used for the secure messaging layer.
     * Used to encrypt the hash of the entire message with the private key to ensure message integrity.
     */
    private Mac mac;

    /**
     * GSON engine used for parsing JSON in Bittrex API call responses.
     */
    private Gson gson;

    static {
        DATE_PARSER.setTimeZone(TIME_ZONE);
        DATE_PARSER_NO_MILLIS.setTimeZone(TIME_ZONE);
    }

    private long getNonceValue() {
        return System.currentTimeMillis() / 1000; // set the initial nonce used in the secure messaging.
    }

    @Override
    public void init(ExchangeConfig config) {

        LOG.info(() -> "About to initialise Bittrex ExchangeConfig: " + config);
        setAuthenticationConfig(config);
        setNetworkConfig(config);
        setOtherConfig(config);

        nonce = getNonceValue();
        initSecureMessageLayer();
        initGson();
    }

    // ------------------------------------------------------------------------------------------------
    // Bittrex API Calls adapted to the Trading API.
    // See https://bittrex.com/home/api
    // ------------------------------------------------------------------------------------------------

    @Override
    public MarketOrderBook getMarketOrders(String marketId) throws TradingApiException, ExchangeNetworkException {

        try {

            final Map<String, String> params = getRequestParamMap();
            params.put("market", marketId);
            // We want sells and buys
            params.put("type", "both");

            final ExchangeHttpResponse response = sendPublicRequestToExchange("getorderbook", params);
            LOG.debug(() -> "Market Orders response: " + response);

            if (response.getStatusCode() == HttpURLConnection.HTTP_OK) {

                final Type resultType = new TypeToken<BittrexResponse<BittrexMarketOrderBookResult>>() {}.getType();
                final BittrexResponse bittrexResponse = gson.fromJson(response.getPayload(), resultType);

                final Boolean success = bittrexResponse.success;
                if (success) {

                    // Assume we'll always get something here if errors array is empty; else blow fast wih NPE
                    final BittrexMarketOrderBookResult bittrexMarketOrderBookResult = (BittrexMarketOrderBookResult) bittrexResponse.result;

                    if (bittrexMarketOrderBookResult != null) {

                        final List<MarketOrder> buyOrders = new ArrayList<>();
                        for (BittrexMarketOrder bittrexBuyOrder : bittrexMarketOrderBookResult.buy) {
                            final MarketOrder buyOrder = new MarketOrder(
                                    OrderType.BUY,
                                    bittrexBuyOrder.get(0),
                                    bittrexBuyOrder.get(1),
                                    bittrexBuyOrder.get(0).multiply(bittrexBuyOrder.get(1)));
                            buyOrders.add(buyOrder);
                        }

                        final List<MarketOrder> sellOrders = new ArrayList<>();
                        for (BittrexMarketOrder bittrexSellOrder : bittrexMarketOrderBookResult.sell) {
                            final MarketOrder sellOrder = new MarketOrder(
                                    OrderType.SELL,
                                    bittrexSellOrder.get(0),
                                    bittrexSellOrder.get(1),
                                    bittrexSellOrder.get(0).multiply(bittrexSellOrder.get(1)));
                            sellOrders.add(sellOrder);
                        }

                        return new MarketOrderBook(marketId, sellOrders, buyOrders);

                    } else {
                        final String errorMsg = FAILED_TO_GET_MARKET_ORDERS + response;
                        LOG.error(errorMsg);
                        throw new TradingApiException(errorMsg);
                    }

                } else {
                    final String errorMsg = FAILED_TO_GET_MARKET_ORDERS + response;
                    LOG.error(errorMsg);
                    throw new TradingApiException(errorMsg);
                }

            } else {
                final String errorMsg = FAILED_TO_GET_MARKET_ORDERS + response;
                LOG.error(errorMsg);
                throw new TradingApiException(errorMsg);
            }

        } catch (ExchangeNetworkException | TradingApiException e) {
            throw e;
        } catch (Exception e) {
            LOG.error(UNEXPECTED_ERROR_MSG, e);
            throw new TradingApiException(UNEXPECTED_ERROR_MSG, e);
        }
    }

    @Override
    public List<OpenOrder> getYourOpenOrders(String marketId) throws TradingApiException, ExchangeNetworkException {

        try {

            final Map<String, String> params = getRequestParamMap();
            params.put("market", marketId);

            final ExchangeHttpResponse response = sendMarketRequestToExchange("getopenorders", params);
            LOG.debug(() -> "Open Orders response: " + response);

            if (response.getStatusCode() == HttpURLConnection.HTTP_OK) {

                final Type resultType = new TypeToken<BittrexResponse<BittrexOpenOrderResult>>() {}.getType();
                final BittrexResponse bittrexResponse = gson.fromJson(response.getPayload(), resultType);

                final Boolean success = bittrexResponse.success;
                if (success) {

                    final List<OpenOrder> openOrders = new ArrayList<>();

                    // Assume we'll always get something here if errors array is empty; else blow fast wih NPE
                    final BittrexOpenOrderResult bittrexOpenOrderResult = (BittrexOpenOrderResult) bittrexResponse.result;

                    final Map<String, BittrexOpenOrder> bittrexOpenOrders = bittrexOpenOrderResult.open;
                    for (final Map.Entry<String, BittrexOpenOrder> openOrder : bittrexOpenOrders.entrySet()) {

                        OrderType orderType;
                        final BittrexOpenOrder bittrexOpenOrder = openOrder.getValue();

                        if (!marketId.equalsIgnoreCase(bittrexOpenOrder.Exchange)) {
                            continue;
                        }

                        switch (bittrexOpenOrder.OrderType) {
                            case "LIMIT_BUY":
                                orderType = OrderType.BUY;
                                break;
                            case "LIMIT_SELL":
                                orderType = OrderType.SELL;
                                break;
                            default:
                                throw new TradingApiException(
                                        "Unrecognised order type received in getYourOpenOrders(). Value: " +
                                                openOrder.getValue().OrderType);
                        }

                        final OpenOrder order = new OpenOrder(
                                openOrder.getKey(),
                                toDate(bittrexOpenOrder.Opened),
                                marketId,
                                orderType,
                                bittrexOpenOrder.Limit,
                                bittrexOpenOrder.QuantityRemaining,
                                bittrexOpenOrder.Quantity,
                                //bittrexOpenOrder.cost, // cost == total value of order in API docs, but it's always 0 :-(
                                bittrexOpenOrder.Limit.multiply(bittrexOpenOrder.Quantity)
                        );

                        openOrders.add(order);
                    }

                    return openOrders;

                } else {
                    final String errorMsg = FAILED_TO_GET_OPEN_ORDERS + response;
                    LOG.error(errorMsg);
                    throw new TradingApiException(errorMsg);
                }

            } else {
                final String errorMsg = FAILED_TO_GET_OPEN_ORDERS + response;
                LOG.error(errorMsg);
                throw new TradingApiException(errorMsg);
            }

        } catch (ExchangeNetworkException | TradingApiException e) {
            throw e;
        } catch (Exception e) {
            LOG.error(UNEXPECTED_ERROR_MSG, e);
            throw new TradingApiException(UNEXPECTED_ERROR_MSG, e);
        }
    }

    @Override
    public String createOrder(String marketId, OrderType orderType, BigDecimal quantity, BigDecimal price) throws
            TradingApiException, ExchangeNetworkException {

        try {

            final Map<String, String> params = getRequestParamMap();
            String bittrexOperation;

            params.put("market", marketId);

            if (orderType == OrderType.BUY) {
                bittrexOperation = "buylimit";
            } else if (orderType == OrderType.SELL) {
                bittrexOperation = "selllimit";
            } else {
                final String errorMsg = "Invalid order type: " + orderType
                        + " - Can only be "
                        + OrderType.BUY.getStringValue() + " or "
                        + OrderType.SELL.getStringValue();
                LOG.error(errorMsg);
                throw new IllegalArgumentException(errorMsg);
            }

            params.put("rate", new DecimalFormat("#.########").format(price));
            params.put("quantity", new DecimalFormat("#.########").format(quantity));

            final ExchangeHttpResponse response = sendMarketRequestToExchange(bittrexOperation, params);
            LOG.debug(() -> "Create Order response: " + response);

            if (response.getStatusCode() == HttpURLConnection.HTTP_OK) {

                final Type resultType = new TypeToken<BittrexResponse<BittrexAddOrderResult>>() {}.getType();
                final BittrexResponse bittrexResponse = gson.fromJson(response.getPayload(), resultType);

                final Boolean success = bittrexResponse.success;
                if (success) {

                    // Assume we'll always get something here if errors array is empty; else blow fast wih NPE
                    final BittrexAddOrderResult bittrexAddOrderResult = (BittrexAddOrderResult) bittrexResponse.result;

                    // Just return the first one. Why an array?
                    return bittrexAddOrderResult.uuid;

                } else {
                    final String errorMsg = FAILED_TO_ADD_ORDER + response;
                    LOG.error(errorMsg);
                    throw new TradingApiException(errorMsg);
                }

            } else {
                final String errorMsg = FAILED_TO_ADD_ORDER + response;
                LOG.error(errorMsg);
                throw new TradingApiException(errorMsg);
            }

        } catch (ExchangeNetworkException | TradingApiException e) {
            throw e;
        } catch (Exception e) {
            LOG.error(UNEXPECTED_ERROR_MSG, e);
            throw new TradingApiException(UNEXPECTED_ERROR_MSG, e);
        }
    }

    @Override
    public boolean cancelOrder(String orderId, String marketIdNotNeeded) throws TradingApiException, ExchangeNetworkException {

        try {
            final Map<String, String> params = getRequestParamMap();
            params.put("uuid", orderId);

            final ExchangeHttpResponse response = sendMarketRequestToExchange("cancel", params);
            LOG.debug(() -> "Cancel Order response: " + response);

            if (response.getStatusCode() == HttpURLConnection.HTTP_OK) {

                final BittrexResponse bittrexResponse = gson.fromJson(response.getPayload(), null);

                final Boolean success = bittrexResponse.success;
                if (success) {
                        return true;

                } else {
                    final String errorMsg = FAILED_TO_CANCEL_ORDER + response;
                    LOG.error(errorMsg);
                    throw new TradingApiException(errorMsg);
                }

            } else {
                final String errorMsg = FAILED_TO_CANCEL_ORDER + response;
                LOG.error(errorMsg);
                throw new TradingApiException(errorMsg);
            }

        } catch (ExchangeNetworkException | TradingApiException e) {
            throw e;
        } catch (Exception e) {
            LOG.error(UNEXPECTED_ERROR_MSG, e);
            throw new TradingApiException(UNEXPECTED_ERROR_MSG, e);
        }
    }

    @Override
    public BigDecimal getLatestMarketPrice(String marketId) throws TradingApiException, ExchangeNetworkException {

        try {

            final Map<String, String> params = getRequestParamMap();
            params.put("market", marketId);

            final ExchangeHttpResponse response = sendPublicRequestToExchange("getticker", params);
            LOG.debug(() -> "Latest Market Price response: " + response);

            if (response.getStatusCode() == HttpURLConnection.HTTP_OK) {

                final Type resultType = new TypeToken<BittrexResponse<BittrexTickerResult>>() {}.getType();
                final BittrexResponse bittrexResponse = gson.fromJson(response.getPayload(), resultType);

                final Boolean success = bittrexResponse.success;
                if (success) {

                    // Assume we'll always get something here if errors array is empty; else blow fast wih NPE
                    final BittrexTickerResult tickerResult = (BittrexTickerResult) bittrexResponse.result;

                    return tickerResult.Last;

                } else {
                    final String errorMsg = FAILED_TO_GET_TICKER + response;
                    LOG.error(errorMsg);
                    throw new TradingApiException(errorMsg);
                }

            } else {
                final String errorMsg = FAILED_TO_GET_TICKER + response;
                LOG.error(errorMsg);
                throw new TradingApiException(errorMsg);
            }

        } catch (ExchangeNetworkException | TradingApiException e) {
            throw e;
        } catch (Exception e) {
            LOG.error(UNEXPECTED_ERROR_MSG, e);
            throw new TradingApiException(UNEXPECTED_ERROR_MSG, e);
        }
    }

    @Override
    public BalanceInfo getBalanceInfo() throws TradingApiException, ExchangeNetworkException {

        try {

            final ExchangeHttpResponse response = sendAccountRequestToExchange("getbalances", null);
            LOG.debug(() -> "Balance Info response: " + response);

            if (response.getStatusCode() == HttpURLConnection.HTTP_OK) {

                final Type resultType = new TypeToken<BittrexResponse<BittrexBalanceResult>>() {}.getType();
                final BittrexResponse bittrexResponse = gson.fromJson(response.getPayload(), resultType);

                final Boolean success = bittrexResponse.success;
                if (success) {

                    // Assume we'll always get something here if errors array is empty; else blow fast wih NPE
                    final BittrexBalanceResult balanceResult = (BittrexBalanceResult) bittrexResponse.result;

                    final Map<String, BigDecimal> balancesAvailable = new HashMap<>();
                    final Map<String, BigDecimal> balancesOnHold = new HashMap<>();

                    for (final BittrexBalance entry : balanceResult) {
                        balancesAvailable.put(entry.Currency, entry.Available);
                        balancesOnHold.put(entry.Currency, entry.Pending);
                    }

                    // 2nd arg of BalanceInfo constructor for reserved/on-hold balances is not provided by exchange.
                    return new BalanceInfo(balancesAvailable, balancesOnHold);

                } else {
                    final String errorMsg = FAILED_TO_GET_BALANCE + response;
                    LOG.error(errorMsg);
                    throw new TradingApiException(errorMsg);
                }

            } else {
                final String errorMsg = FAILED_TO_GET_BALANCE + response;
                LOG.error(errorMsg);
                throw new TradingApiException(errorMsg);
            }

        } catch (ExchangeNetworkException | TradingApiException e) {
            throw e;
        } catch (Exception e) {
            LOG.error(UNEXPECTED_ERROR_MSG, e);
            throw new TradingApiException(UNEXPECTED_ERROR_MSG, e);
        }
    }

    @Override
    public BigDecimal getPercentageOfBuyOrderTakenForExchangeFee(String marketId) throws TradingApiException,
            ExchangeNetworkException {
        // Bittrex does not provide API call for fetching % buy fee;
        return buyFeePercentage;
    }

    @Override
    public BigDecimal getPercentageOfSellOrderTakenForExchangeFee(String marketId) throws TradingApiException,
            ExchangeNetworkException {
        // Bittrex does not provide API call for fetching % buy fee;
        return sellFeePercentage;
    }

    @Override
    public String getImplName() {
        return "Bittrex API v1.1";
    }

    // ------------------------------------------------------------------------------------------------
    //  GSON classes for JSON responses.
    //  See https://www.kraken.com/en-gb/help/api
    // ------------------------------------------------------------------------------------------------

    /**
     * GSON base class for all Bittrex responses.
     * <p>
     * All Bittrex responses have the following format:
     * <p>
     * <pre>
     *
     * success = result of the api call:
     * message = message if errors are returned
     *
     * result = result of API call (may not be present if errors occur)
     *
     * </pre>
     * <p>
     * The result Type is what varies with each API call.
     */
    private static class BittrexResponse<T> {

        // field names map to the JSON arg names
        public Boolean success;
        public String message;
        public T result; // TODO fix up the Generics abuse ;-o

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("success", success)
                    .add("message", message)
                    .add("result", result)
                    .toString();
        }
    }

    /**
     * GSON class that wraps Depth API call result - the Market Order Book.
     */
    private static class BittrexMarketOrderBookResult {
        public List<BittrexMarketOrder> buy;
        public List<BittrexMarketOrder> sell;

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("buy", buy)
                    .add("sell", sell)
                    .toString();
        }
    }

    /**
     * GSON class that wraps a Balance API call result.
     */
    private static class BittrexBalanceResult extends ArrayList<BittrexBalance> {
    }

    /**
     * GSON class that wraps a Balance API call result.
     */
    private static class BittrexBalance {
        private String Currency;
        public BigDecimal Balance;
        private BigDecimal Available;
        private BigDecimal Pending;
        private String CryptoAdress;
        private Boolean Requested;
        private String Uuid;

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("Currency", Currency)
                    .add("Balance", Balance)
                    .add("Available", Available)
                    .add("Pending", Pending)
                    .add("CryptoAdress", CryptoAdress)
                    .add("Requested", Requested)
                    .add("Uuid", Uuid)
                    .toString();
        }
    }

    /**
     * GSON class that wraps a Ticker API call result.
     */
    private static class BittrexTickerResult {
        private BigDecimal Bid;
        private BigDecimal Ask;
        private BigDecimal Last;

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("Bid", Bid)
                    .add("Ask", Ask)
                    .add("Last", Last)
                    .toString();
        }
    }

    /**
     * GSON class that wraps an Open Order API call result - your open orders.
     */
    private static class BittrexOpenOrderResult {

        public Map<String, BittrexOpenOrder> open;

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("open", open)
                    .toString();
        }
    }

    /**
     * GSON class the represents a Bittrex Open Order.
     */
    private static class BittrexOpenOrder {

        // field names map to the JSON arg names
        private String uuid;
        private String OrderUuid;
        public String Exchange;
        public String OrderType;
        private BigDecimal Quantity;
        private BigDecimal QuantityRemaining;
        private BigDecimal Limit;
        private BigDecimal CommissionPaid;
        public BigDecimal Price;
        private BigDecimal PricePerUnit;
        private String Opened;
        private String Closed;
        private Boolean CancelInitiated;
        private Boolean ImmediateOrCancel;
        private Boolean IsConditional;
        private String Condition;
        private String ConditionTarget;



        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("uuid", uuid)
                    .add("OrderUuid", OrderUuid)
                    .add("Exchange", Exchange)
                    .add("OrderType", OrderType)
                    .add("Quantity", Quantity)
                    .add("QuantityRemaining", QuantityRemaining)
                    .add("Limit", Limit)
                    .add("CommissionPaid", CommissionPaid)
                    .add("Price", Price)
                    .add("PricePerUnit", PricePerUnit)
                    .add("Opened", Opened)
                    .add("Closed", Closed)
                    .add("CancelInitiated", CancelInitiated)
                    .add("ImmediateOrCancel", ImmediateOrCancel)
                    .add("IsConditional", IsConditional)
                    .add("Condition", Condition)
                    .add("ConditionTarget", ConditionTarget)
                    .toString();
        }
    }


    /**
     * GSON class representing an AddOrder result.
     */
    private static class BittrexAddOrderResult {

        private String uuid; // why is this a list/array?

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("uuid", uuid)
                    .toString();
        }
    }


//    /**
//     * GSON class representing a CancelOrder result.
//     */
//    private static class BittrexCancelOrderResult {
//
//        public int count;
//
//        @Override
//        public String toString() {
//            return MoreObjects.toStringHelper(this)
//                    .add("count", count)
//                    .toString();
//        }
//    }


    /**
     * GSON class for holding Market Orders.
     * First element in array is Quantity, second element is Rate
     */
    private static class BittrexMarketOrder extends ArrayList<BigDecimal> {
        private static final long serialVersionUID = -4959711260742077759L;
    }


    // ------------------------------------------------------------------------------------------------
    //  Transport layer methods
    // ------------------------------------------------------------------------------------------------

    /**
     * Makes a public API call to the Bittrex exchange.
     *
     * @param apiMethod the API method to call.
     * @param params    any (optional) query param args to use in the API call.
     * @return the response from the exchange.
     * @throws ExchangeNetworkException if there is a network issue connecting to exchange.
     * @throws TradingApiException      if anything unexpected happens.
     */
    private ExchangeHttpResponse sendPublicRequestToExchange(String apiMethod, Map<String, String> params)
            throws ExchangeNetworkException, TradingApiException {

        if (params == null) {
            params = new HashMap<>(); // no params, so empty query string
        }

        // Build the query string with any given params
        final StringBuilder queryString = new StringBuilder("?");
        for (final String param : params.keySet()) {
            if (queryString.length() > 1) {
                queryString.append("&");
            }
            //noinspection deprecation
            queryString.append(param).append("=").append(URLEncoder.encode(params.get(param)));
        }

        // Request headers required by Exchange
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("Content-Type", "application/x-www-form-urlencoded");

        try {

            final URL url = new URL(PUBLIC_API_BASE_URL + apiMethod + queryString);
            return sendNetworkRequest(url, "GET", null, requestHeaders);

        } catch (MalformedURLException e) {
            final String errorMsg = UNEXPECTED_IO_ERROR_MSG;
            LOG.error(errorMsg, e);
            throw new TradingApiException(errorMsg, e);
        }
    }

    /**
     * Makes a private API call to the Bittrex exchange in the Market Group
     *
     * @param apiMethod the API method to call.
     * @param params    any (optional) query param args to use in the API call.
     * @return the response from the exchange.
     * @throws ExchangeNetworkException if there is a network issue connecting to exchange.
     * @throws TradingApiException      if anything unexpected happens.
     */
    private ExchangeHttpResponse sendMarketRequestToExchange(String apiMethod, Map<String, String> params)
            throws ExchangeNetworkException, TradingApiException {

        String url = buildURL(MARKET_API_BASE_URL, apiMethod, params);
        String signature = buildURLSignature(url);
        return sendAuthenticatedRequestToExchange(url, signature);
    }

    /**
     * Makes a private API call to the Bittrex exchange in the Account Group
     *
     * @param apiMethod the API method to call.
     * @param params    any (optional) query param args to use in the API call.
     * @return the response from the exchange.
     * @throws ExchangeNetworkException if there is a network issue connecting to exchange.
     * @throws TradingApiException      if anything unexpected happens.
     */
    private ExchangeHttpResponse sendAccountRequestToExchange(String apiMethod, Map<String, String> params)
            throws ExchangeNetworkException, TradingApiException {

        String url = buildURL(ACCOUNT_API_BASE_URL, apiMethod, params);
        String signature = buildURLSignature(url);
        return sendAuthenticatedRequestToExchange(url, signature);

    }

    /**
     * Create the URL String for the call to the Bittrex API
     * @param apiMethod the api method as defined in the Bittrex API
     * @param params the Query params
     * @return the formatted URL
     */
    private String buildURL(String baseURL, String apiMethod, Map<String, String> params) {
        String url = baseURL;
        url += apiMethod;

        if (params == null) {
            // create empty map for non param API calls, e.g. "trades"
            params = new HashMap<>();
        }

        // The nonce is required by Bittrex in every request.
        // It MUST be incremented each time and the nonce param MUST match the value used in signature.
        nonce++;
        params.put("nonce", Long.toString(nonce));

        // The API Key must be in every request too.
        params.put("apikey", key);

        // Build the URL with query param args in it - yuk!
        StringBuilder postData = new StringBuilder();
        for (final String param : params.keySet()) {
            if (postData.length() > 0) {
                postData.append("&");
            }
            //noinspection deprecation
            postData.append(param).append("=").append(URLEncoder.encode(params.get(param)));
        }
        if (postData.length() > 0) {
            postData.insert(0, "?");
        }
        return url + postData;
    }

    /**
     * Build the requested signature for Bittrex API calls
     * @param request the request URL, including params
     * @return the signature string
     * @throws TradingApiException if anything unexpected happens
     */
    String buildURLSignature(String request) throws TradingApiException {
        if (!initializedMACAuthentication) {
            final String errorMsg = "MAC Message security layer has not been initialized.";
            LOG.error(errorMsg);
            throw new IllegalStateException(errorMsg);
        }

        try {
            mac.reset();
            // Create hmac_sha512 digest of path and api secret
            mac.update(request.getBytes("UTF-8"));

            // Signature in Base64

            return String.format("%0128x", new BigInteger(1, mac.doFinal()));

        } catch (UnsupportedEncodingException e) {

            final String errorMsg = UNEXPECTED_IO_ERROR_MSG;
            LOG.error(errorMsg, e);
            throw new TradingApiException(errorMsg, e);
        }
    }

    /**
     * <p>
     * Makes an Account API call to the Bittrex exchange.
     * </p>
     * <p>
     * <pre>
     * Bittrex requires the following HTTP headers to bet set:
     *
     * apisign = Message signature using HMAC-SHA512 of URI path and base64 decoded secret API key
     *
     * The nonce must always increasing unsigned 64 bit integer.
     *
     * Note: Sometimes requests can arrive out of order or NTP can cause your clock to rewind, resulting in nonce issues.
     * If you encounter this issue, you can change the nonce window in your account API settings page.
     * The amount to set it to depends upon how you increment the nonce. Depending on your connectivity, a setting that
     * would accommodate 3-15 seconds of network issues is suggested.
     *
     * </pre>
     *
     * @param url the URL of the api call
     * @param signature    the signature to put on header.
     * @return the response from the exchange.
     * @throws ExchangeNetworkException if there is a network issue connecting to exchange.
     * @throws TradingApiException      if anything unexpected happens.
     */
    private ExchangeHttpResponse sendAuthenticatedRequestToExchange(final String url, final String signature)
            throws ExchangeNetworkException, TradingApiException {

        try {

            final URL finalURL = new URL(url);

            // Request headers required by Exchange
            final Map<String, String> requestHeaders = new HashMap<>();
            //requestHeaders.put("Content-Type", "application/x-www-form-urlencoded");
            requestHeaders.put("apisign", signature);

            return sendNetworkRequest(finalURL, "POST", "", requestHeaders);

        } catch (MalformedURLException e) {

            final String errorMsg = UNEXPECTED_IO_ERROR_MSG;
            LOG.error(errorMsg, e);
            throw new TradingApiException(errorMsg, e);
        }
    }

    /**
     * Initialises the secure messaging layer
     * Sets up the MAC to safeguard the data we send to the exchange.
     * We fail hard n fast if any of this stuff blows.
     */
    private void initSecureMessageLayer() {

        try {
            // Bittrex secret key is in Base64, so we need to decode it first
            final byte[] base64DecodedSecret;
            try {
                base64DecodedSecret = secret.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }

            final SecretKeySpec keyspec = new SecretKeySpec(base64DecodedSecret, "HmacSHA512");
            mac = Mac.getInstance("HmacSHA512");
            mac.init(keyspec);
            initializedMACAuthentication = true;
        } catch (NoSuchAlgorithmException e) {
            final String errorMsg = "Failed to setup MAC security. HINT: Is HmacSHA512 installed?";
            LOG.error(errorMsg, e);
            throw new IllegalStateException(errorMsg, e);
        } catch (InvalidKeyException e) {
            final String errorMsg = "Failed to setup MAC security. Secret key seems invalid!";
            LOG.error(errorMsg, e);
            throw new IllegalArgumentException(errorMsg, e);
        }
    }

    // ------------------------------------------------------------------------------------------------
    //  Config methods
    // ------------------------------------------------------------------------------------------------

    private void setAuthenticationConfig(ExchangeConfig exchangeConfig) {
        final AuthenticationConfig authenticationConfig = getAuthenticationConfig(exchangeConfig);
        key = getAuthenticationConfigItem(authenticationConfig, KEY_PROPERTY_NAME);
        secret = getAuthenticationConfigItem(authenticationConfig, SECRET_PROPERTY_NAME);
    }

    private void setOtherConfig(ExchangeConfig exchangeConfig) {

        final OtherConfig otherConfig = getOtherConfig(exchangeConfig);

        final String buyFeeInConfig = getOtherConfigItem(otherConfig, BUY_FEE_PROPERTY_NAME);
        buyFeePercentage = new BigDecimal(buyFeeInConfig).divide(new BigDecimal("100"), 8, BigDecimal.ROUND_HALF_UP);
        LOG.info(() -> "Buy fee % in BigDecimal format: " + buyFeePercentage);

        final String sellFeeInConfig = getOtherConfigItem(otherConfig, SELL_FEE_PROPERTY_NAME);
        sellFeePercentage = new BigDecimal(sellFeeInConfig).divide(new BigDecimal("100"), 8, BigDecimal.ROUND_HALF_UP);
        LOG.info(() -> "Sell fee % in BigDecimal format: " + sellFeePercentage);
    }

    // ------------------------------------------------------------------------------------------------
    //  Util methods
    // ------------------------------------------------------------------------------------------------

    /**
     * Initialises the GSON layer.
     */
    private void initGson() {
        final GsonBuilder gsonBuilder = new GsonBuilder();
        gson = gsonBuilder.create();
    }

    /*
     * Hack for unit-testing map params passed to transport layer.
     */
    private Map<String, String> getRequestParamMap() {
        return new HashMap<>();
    }

    private static Date toDate(String dateString) throws TradingApiException {

        try {
            return DATE_PARSER.parse(dateString);
        } catch (ParseException e) {
            try {
                return DATE_PARSER_NO_MILLIS.parse(dateString);
            } catch (ParseException e1) {
                throw new TradingApiException("Illegal date/time format", e1);
            }
        }
    }

    }
