package com.demo.boot.algorand.util;

import com.algorand.algosdk.account.Account;
import com.algorand.algosdk.crypto.Address;
import com.algorand.algosdk.kmd.client.ApiException;
import com.algorand.algosdk.kmd.client.KmdClient;
import com.algorand.algosdk.kmd.client.api.KmdApi;
import com.algorand.algosdk.kmd.client.model.*;
import com.algorand.algosdk.transaction.SignedTransaction;
import com.algorand.algosdk.transaction.Transaction;
import com.algorand.algosdk.util.Encoder;
import com.algorand.algosdk.v2.client.algod.TransactionParams;
import com.algorand.algosdk.v2.client.common.AlgodClient;
//import com.algorand.algosdk.v2.client.common.IndexerClient;
import com.algorand.algosdk.v2.client.common.Response;
import com.algorand.algosdk.v2.client.model.PendingTransactionResponse;
import com.algorand.algosdk.v2.client.model.TransactionParametersResponse;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AssetTransfer {

    private static final String TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String KMD_API_ADDR = "http://localhost";
    private static final String ALGOD_API_ADDR = "localhost";
    private  static  final int KMD_PORT = 4002;
    private  static  final int ALGOD_PORT = 4001;
    //private static final int INDEX_PORT = 8980;
    private static KmdApi kmd = null;
    private static AlgodClient client = null;
    private static String[] HEADERS =  {"X-API-Key"};
    private static String[] VALUES = {TOKEN};
    // Get accounts from sandbox.
    private static String WALLET_HANDLE;
    private static List<Address> ACCOUNTS;

    static {
        try {
            kmd = getKmdApi();
            WALLET_HANDLE = getDefaultWalletHandle();
            ACCOUNTS = getWalletAccounts(WALLET_HANDLE);
        } catch (ApiException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        // Initialize algod/indexer v2 clients.
        client = connectToNetwork();
        //IndexerClient indexer = new IndexerClient(ALGOD_API_ADDR, INDEX_PORT);

        byte[] privateKey = lookupPrivateKey(ACCOUNTS.get(0), WALLET_HANDLE);
        Account account = new Account(privateKey);

        byte[] privateKey2 = lookupPrivateKey(ACCOUNTS.get(1), WALLET_HANDLE);
        Account account2 = new Account(privateKey2);

        Long assetId = getFirstCreatedAsset(account);

        /*Transaction optinTx = createOptinTransaction(assetId);
        SignedTransaction stx = signTransactionWithKMD(optinTx, WALLET_HANDLE);

        String transactionId = submitTransaction(stx);
        System.out.println("Transaction ID: " + transactionId);

        waitForConfirmation(transactionId);*/

        Transaction transferTx = createTransferTransferTransaction(assetId);
        SignedTransaction stx2 = signTransactionWithKMD(transferTx, WALLET_HANDLE);
        //SignedTransaction stx2 = account2.signTransaction(transferTx);

        //TODO: debug the line below.
        String transactionId2 = submitTransaction(stx2);
        System.out.println("Transfer Transaction ID: " + stx2.transactionID);

        waitForConfirmation(transactionId2);

        printCreatedAsset(account, 1L);
        printAssetHolding(account2, 1L);

    }

    private static KmdApi getKmdApi() {
        // Initialize KMD v1 client
        KmdClient kmdClient = new KmdClient();
        kmdClient.setBasePath(KMD_API_ADDR+":"+KMD_PORT);
        kmdClient.setApiKey(TOKEN);
        return new KmdApi(kmdClient);
    }

    private static AlgodClient connectToNetwork() throws Exception {
        if (Objects.isNull(client)) {
            client = new AlgodClient(ALGOD_API_ADDR, ALGOD_PORT, TOKEN);
        }
        System.out.println(client.GetAssetByID(1L));
        return client;
    }

    private static Transaction getCreateAssetTransaction(AlgodClient algod, List<Address> accounts, String metadataHash, byte[] gh) throws Exception {
        Transaction createAssetTx = Transaction.AssetCreateTransactionBuilder()
                .lookupParams(algod)
                .sender(accounts.get(0))
                .fee(100)
                .firstValid(322575)
                .lastValid(323575)
                .genesisHash(gh)
                .assetName("PMUC")
                .assetUnitName("UC")
                .assetTotal(1000)
                .assetDecimals(1)
                .metadataHashUTF8(metadataHash)
                .clawback(accounts.get(0))
                .freeze(accounts.get(0))
                .manager(accounts.get(0))
                .build();
        return createAssetTx;
    }
    public static Long getFirstCreatedAsset(Account account) throws Exception {
        Long assetID = null;
        client = connectToNetwork();
        String accountInfo = client.AccountInformation(account.getAddress()).execute().toString();

        Response<com.algorand.algosdk.v2.client.model.Account> response =
                client.AccountInformation(account.getAddress()).execute();

        System.out.println("AccountInfo: " + accountInfo);
        JSONObject jsonObj = new JSONObject(accountInfo.toString());
        JSONArray jsonArray = (JSONArray) jsonObj.get("created-assets");
        if (jsonArray.length() > 0) {
            try {
                JSONObject o = (JSONObject) jsonArray.get(0);
                Integer assetId = (Integer) o.get("index");
                System.out.println("Created Asset Info: " + o.toString(2)); // pretty print

                assetID =  assetId.longValue();
            } catch (Exception e) {
                throw (e);
            }
        }
        return assetID;
    }
    // utility function to print created asset
    public static void printCreatedAsset(Account account, Long assetID) throws Exception {
        client = connectToNetwork();
        String accountInfo = client.AccountInformation(account.getAddress()).execute().toString();

        Response<com.algorand.algosdk.v2.client.model.Account> response =
                client.AccountInformation(account.getAddress()).execute();

        System.out.println("AccountInfo: " + accountInfo);
        JSONObject jsonObj = new JSONObject(accountInfo.toString());
        JSONArray jsonArray = (JSONArray) jsonObj.get("created-assets");
        if (jsonArray.length() > 0) {
            try {
                for (Object o : jsonArray) {
                    JSONObject ca = (JSONObject) o;
                    Integer myassetIDInt = (Integer) ca.get("index");
                    if (assetID.longValue() == myassetIDInt.longValue()) {
                        System.out.println("Created Asset Info: " + ca.toString(2)); // pretty print
                        break;
                    }
                }
            } catch (Exception e) {
                throw (e);
            }
        }
    }

    // utility function to print asset holding
    public static void printAssetHolding(Account account, Long assetID) throws Exception {
        client = connectToNetwork();

        String accountInfo = client.AccountInformation(account.getAddress()).execute().toString();
        JSONObject jsonObj = new JSONObject(accountInfo);
        JSONArray jsonArray = (JSONArray) jsonObj.get("assets");
        if (jsonArray.length() > 0) {
            try {
                for (Object o : jsonArray) {
                    JSONObject ca = (JSONObject) o;
                    Integer myassetIDInt = (Integer) ca.get("asset-id");
                    if (assetID.longValue() == myassetIDInt.longValue()) {
                        System.out.println("Asset Holding Info: " + ca.toString(2)); // pretty print
                        break;
                    }
                }
            } catch (Exception e) {
                throw (e);
            }
        }
    }

    public static Transaction createOptinTransaction(Long assetID) throws Exception {
        client = connectToNetwork();
        TransactionParametersResponse params = client.TransactionParams().execute().body();
        params.fee = (long) 100;

        // configuration changes must be done by
        // the manager account - changing manager of the asset
        Transaction tx = Transaction.AssetAcceptTransactionBuilder().acceptingAccount(ACCOUNTS.get(1)).assetIndex(assetID)
                .suggestedParams(params).build();

        return tx;
    }

    public static Transaction createTransferTransferTransaction(Long assetID) throws  Exception {

        client = connectToNetwork();
        TransactionParametersResponse params = client.TransactionParams().execute().body();
        params.fee = (long) 100;

        // set asset xfer specific parameters
        BigInteger assetAmount = BigInteger.valueOf(1);
        Address sender = ACCOUNTS.get(0);
        Address receiver = ACCOUNTS.get(1);

        System.out.println("assetID:" + assetID);
        System.out.println("Sender: " + sender);
        System.out.println("Receiver: "  + receiver);
        Transaction tx = Transaction.AssetTransferTransactionBuilder().sender(sender).assetReceiver(receiver)
                .assetAmount(assetAmount).assetIndex(assetID).suggestedParams(params).build();

        return tx;
    }


    public static SignedTransaction signTransactionWithKMD(Transaction tx, String walletHandle) throws IOException, ApiException {
        SignTransactionRequest req = new SignTransactionRequest();
        req.transaction(Encoder.encodeToMsgPack(tx));
        req.setWalletHandleToken(walletHandle);
        req.setWalletPassword("");
        byte[] stxBytes = kmd.signTransaction(req).getSignedTransaction();
        return Encoder.decodeFromMsgPack(stxBytes, SignedTransaction.class);
    }

    public static byte[] lookupPrivateKey(Address addr, String walletHandle) throws ApiException {
        System.out.println("Address:" + addr.toString());
        ExportKeyRequest req = new ExportKeyRequest();
        req.setAddress(addr.toString());
        req.setWalletHandleToken(walletHandle);
        req.setWalletPassword("");
        return kmd.exportKey(req).getPrivateKey();
    }

    public static String getDefaultWalletHandle() throws ApiException {
        for (APIV1Wallet w : kmd.listWallets().getWallets()) {
            if (w.getName().equals("unencrypted-default-wallet")) {
                InitWalletHandleTokenRequest tokenreq = new InitWalletHandleTokenRequest();
                tokenreq.setWalletId(w.getId());
                tokenreq.setWalletPassword("");
                return kmd.initWalletHandleToken(tokenreq).getWalletHandleToken();
            }
        }
        throw new RuntimeException("Default wallet not found.");
    }

    public static List<Address> getWalletAccounts(String walletHandle) throws ApiException, NoSuchAlgorithmException {
        List<Address> accounts = new ArrayList<>();

        ListKeysRequest keysRequest = new ListKeysRequest();
        keysRequest.setWalletHandleToken(walletHandle);
        for (String addr : kmd.listKeysInWallet(keysRequest).getAddresses()) {
            accounts.add(new Address(addr));
        }

        return accounts;
    }

    public static String submitTransaction(SignedTransaction signedTx) throws Exception {

        client = connectToNetwork();
        try {
            // Msgpack encode the signed transaction
            byte[] encodedTxBytes = Encoder.encodeToMsgPack(signedTx);
            String id = client.RawTransaction().rawtxn(encodedTxBytes).execute().body().txId;
            return (id);
        } catch (ApiException e) {
            System.out.println("ApiException: " + e.getResponseBody());
            throw (e);
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            throw (e);
        }
    }

    // utility function to wait on a transaction to be confirmed

    public static void waitForConfirmation(String txID) throws Exception {
        if (client == null)
            client = connectToNetwork();

        Long lastRound = client.GetStatus().execute().body().lastRound;

        while (true) {
            try {
                // Check the pending tranactions
                Response<PendingTransactionResponse> pendingInfo = client.PendingTransactionInformation(txID).execute();
                if (pendingInfo.body().confirmedRound != null && pendingInfo.body().confirmedRound > 0) {
                    // Got the completed Transaction
                    System.out.println(
                            "Transaction " + txID + " confirmed in round " + pendingInfo.body().confirmedRound);
                    break;
                }
                lastRound++;
                client.WaitForBlock(lastRound).execute();
            } catch (Exception e) {
                throw (e);
            }
        }
    }
}
