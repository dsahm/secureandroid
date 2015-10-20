package my.secureandroid;

import android.content.Context;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.LinkedList;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MACCrypto extends CryptoIOHelper {

    private static final String NO_ALG_MSG = "No suitable algorithm available on this platform";
    // Default Instances and Modes for Encryption/Decryption
    private static final String MAC_INSTANCE = "MAC";
    private String MAC_ALGORITHM;
    private String PBE_ALGORITHM;
    // Key lengths, iterations, salt lengths
    private static final int MAC_128 = 128;
    private static final int PBE_SALT_LENGTH_BYTE = 64;
    private static int PBE_ITERATIONS;
    // Constants
    private static final String MAC_ALIAS = "SecureAndroid.MacIv.Alias";
    // Exception messages
    private static final String WRONG_MODE_EXCEPTION = "Wrong mode, choose SecureAndroid.FILE or SecureAndroid.SHARED_PREFERENCES";

    /**
     * Constructor for MACCrypto Class. Sets the context of the superclass.
     * @param context The context.
     * @param iterations The iteration count for hashing.
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    public MACCrypto(Context context, int iterations) throws NoAlgorithmAvailableException {
        // Call superclass
        super(context);
        // Check provider availability
        providerCheckMacCrypto();
        // Apply Googles pseudo random number generator fix for API-Level 16-18
        fixPrng();
        // set the iteration count
        PBE_ITERATIONS = iterations;
    }

    /**
     * Generates and returns a 128-Bit long Mac-Key.
     * @return              The generated Mac-Key
     * @throws              NoSuchAlgorithmException
     */
    public SecretKey generateMacKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGenerator;
        keyGenerator = KeyGenerator.getInstance(MAC_ALGORITHM);
        keyGenerator.init(MAC_128);
        return keyGenerator.generateKey();
    }

    /**
     * Method to generate a Message Authentication Code.
     * @param cipher    the ciphertext for which the mac should be generated
     * @param macKey    the secret key for the mac generation
     * @return          mac as byte array
     * @throws GeneralSecurityException
     */
    public byte[] generateMac(byte[] cipher, SecretKey macKey) throws GeneralSecurityException {
        final Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        return mac.doFinal(cipher);
    }

    /**
     * Generates a MAC-Key from the given password with the given kelength. If the keylength is
     * not 128 Bit, it will be set to 128 Bit.
     * @param password      the password
     * @return              the SaltAndKey object
     * @throws GeneralSecurityException
     */
    public SaltAndKey generateRandomMacKeyFromPasswordGetSalt(char[] password) throws GeneralSecurityException {
        final byte[] salt = super.generateRandomBytes(PBE_SALT_LENGTH_BYTE);
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, MAC_128);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        return new SaltAndKey(new SecretKeySpec(temp, MAC_INSTANCE), salt);
//        return new SaltAndKey(keyFactory.generateSecret(keySpec), salt);
    }

    /**
     * Returns the Secret-MAC key generated with the specified salt value and the password.
     * @param password      The password used to derive the key.
     * @param salt          The salt used to derive the key.
     * @return              The secret MAC-Key.
     * @throws GeneralSecurityException
     */
    public SecretKey generateMacKeyFromPasswordSetSalt(char[] password, byte[] salt) throws GeneralSecurityException {
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, MAC_128);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(temp, MAC_INSTANCE);
//        return keyFactory.generateSecret(keySpec);
    }

    /**
     *
     * @param mode      The mode for storage, choose SecureAndroid.SHARED_PREFERENCES or
     *                  SecureAndroid.FILE.
     * @param alias     The alias for SharedPref or the file.
     * @return          The MAC.
     * @throws IOException
     * @throws CryptoIOHelper.WrongModeException
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    public byte[] loadMAC(int mode, String alias) throws IOException, CryptoIOHelper.WrongModeException, CryptoIOHelper.DataNotAvailableException {
        if (mode == SecureAndroid.SHARED_PREFERENCES) {
            return super.loadFromSharedPrefBase64(MAC_ALIAS, alias);
        } else if (mode == SecureAndroid.FILE) {
            return super.readBytesFromFile(alias);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_MODE_EXCEPTION);
        }
    }

    /**
     * Method the check the integrity of the given ciphertext against the given MAC with
     * the given Secretkey
     * @param cipherText    the ciphertext to be checked
     * @param mac           the Message Authentication code against which to check
     * @param macKey        the secretkey
     * @return              true if check was successful, false otherwise
     * @throws GeneralSecurityException
     */
    public boolean checkIntegrity(byte[] cipherText, byte[] mac, SecretKey macKey) throws GeneralSecurityException {
        return Arrays.equals(mac, this.generateMac(cipherText, macKey));
    }


    /**
     * Checks whether a suitable algorithm for PBKD is available.
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    private void providerCheckMacCrypto() throws NoAlgorithmAvailableException {
        final LinkedList<String> algorithms = super.providerCheck();
        if (algorithms.contains("PBKDF2WithHmacSHA256")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA256";
        } else if (algorithms.contains("PBKDF2WithHmacSHA1")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
        } else {
            //PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
            throw new NoAlgorithmAvailableException(NO_ALG_MSG);
        }
        if (algorithms.contains("HmacSHA256")) {
            MAC_ALGORITHM = "HmacSHA256";
//            Log.i("Info MACCrypto", "HmacSHA256");
        } else if (algorithms.contains("HMACSHA256")) {
            MAC_ALGORITHM = "HMACSHA256";
//            Log.i("Info MACCrypto", "HMACSHA256");
        } else if (algorithms.contains("HmacSHA1")) {
//            Log.i("Info MACCrypto", "HmacSHA1");
            MAC_ALGORITHM = "HmacSHA1";
        } else if (algorithms.contains("HMACSHA1")) {
//            Log.i("Info MACCrypto", "HMACSHA1");
            MAC_ALGORITHM = "HMACSHA1";
        } else {
            throw new NoAlgorithmAvailableException(NO_ALG_MSG);
        }
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     * Will only run once, and every subsequent call should return immediately.
     */
    private static void fixPrng() {
        synchronized (PRNGFixes.class) {
            PRNGFixes.apply();
        }
    }

    // Not yet needed

    /**
     * Saves MAC-Key to specified file, encoded in Base64. The file is only accessible by
     * your app.
     * @param secretKey     the secret MAC-key
     * @param filename      the file in which the key should be stored
     * @throws IOException
     */
    public void saveMACKeyToFileBase64(SecretKey secretKey, String filename) throws IOException {
        super.saveBytesToFileBase64(filename, secretKey.getEncoded());
    }

    /**
     * Retrieves and returns the MAC-Key saved in the specified file.
     * @param filename      the filename
     * @return              the MAC-Key
     * @throws IOException
     */
    public SecretKey getMACKeyFromFile(String filename) throws IOException {
        byte[] temp = super.readBytesFromFile(filename);
        return new SecretKeySpec(temp, 0, temp.length, MAC_INSTANCE);
    }

    /**
     * Saves MAC-Key to specified SharePrefs, encoded in Base64. The file is only accessible by
     * your app.
     * @param spAlias       the alias for the SharedPref
     * @param keyAlias      the alias under which the key is stored in SharePref
     * @param secretKey     the MAC-Key to be saved
     */
    public void saveMACKeyToSharedPrefBase64(String spAlias, String keyAlias, SecretKey secretKey) {
        super.saveToSharedPrefBase64(spAlias, keyAlias, secretKey.getEncoded());
    }

    /**
     * Retrieves and returns the MAC-Key saved in the specified SharePrefs.
     * @param spAlias     the alias for the SharedPref
     * @param keyAlias    the alias under which the key is stored in SharePref
     * @return            the MAC-Key
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    public SecretKey getMACKeyFromSharedPref(String spAlias, String keyAlias) throws DataNotAvailableException {
        byte[] temp = super.loadFromSharedPrefBase64(spAlias, keyAlias);
        return new SecretKeySpec(temp, 0, temp.length, MAC_INSTANCE);
    }
}