package my.secureandroid;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class that implements cryptographic MAC-operations.
 */

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
    private static final String MAC_ALIAS = "SecureAndroid.MACIv.Alias";
    // Exception messages
    private static final String WRONG_MODE_EXCEPTION = "Wrong mode, choose SecureAndroid.Mode.FILE or SecureAndroid.Mode.SHARED_PREFERENCES";
    // For PRNG-Fix
    private static AtomicBoolean prng = new AtomicBoolean(false);

    /**
     * Constructor for MACCrypto Class. Sets the context of the superclass.
     *
     * @param context The context.
     * @param iterations The iteration count for hashing/PBDKF.
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    protected MACCrypto(Context context, int iterations) throws NoAlgorithmAvailableException {
        // Call superclass
        super(context);
        // Check provider availability
        providerCheckMACCrypto();
        // Apply Googles pseudo random number generator fix for API-Level 16-18
        prng = new AtomicBoolean(false);
        fixPrng();
        // set the iteration count
        PBE_ITERATIONS = iterations;
    }

    /**
     * Generates and returns a 128 Bit long MAC-Key.
     *
     * @return              The generated MAC-Key.
     * @throws              NoSuchAlgorithmException
     */
    protected SecretKey generateRandomMACKey() throws NoSuchAlgorithmException{
        fixPrng();
        KeyGenerator keyGenerator;
        keyGenerator = KeyGenerator.getInstance(MAC_ALGORITHM);
        keyGenerator.init(MAC_128);
        return keyGenerator.generateKey();
    }

    /**
     * Method to generate a Message Authentication Code.
     *
     * @param cipher    The ciphertext for which the mac should be generated.
     * @param macKey    The secret key for the mac generation.
     * @return          MAC as byte array.
     * @throws GeneralSecurityException
     */
    protected byte[] generateMAC(byte[] cipher, SecretKey macKey) throws GeneralSecurityException {
        final Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        return mac.doFinal(cipher);
    }

    /**
     * Generates a MAC-Key from the given password.
     *
     * @param password      The password.
     * @return              The SaltAndKey object.
     * @throws GeneralSecurityException
     */
    protected SaltAndKey generateRandomMACKeyFromPasswordGetSalt(char[] password) throws GeneralSecurityException {
        fixPrng();
        final byte[] salt = super.generateRandomBytes(PBE_SALT_LENGTH_BYTE);
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, MAC_128);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        return new SaltAndKey(new SecretKeySpec(temp, MAC_INSTANCE), salt);
    }

    /**
     * Returns the Secret-MAC key generated with the specified salt value and password.
     *
     * @param password      The password used to derive the key.
     * @param salt          The salt used to derive the key.
     * @return              The secret MAC-Key.
     * @throws GeneralSecurityException
     */
    protected SecretKey generateRandomMACKeyFromPasswordSetSalt(char[] password, byte[] salt) throws GeneralSecurityException {
        fixPrng();
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, MAC_128);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(temp, MAC_INSTANCE);
    }

    /**
     * Method to load a MAC.
     *
     * @param mode      The mode for storage, choose SecureAndroid.Mode.SHARED_PREFERENCES or FILE.
     * @param alias     The alias for SharedPref or the file.
     * @return          The MAC.
     * @throws IOException
     * @throws IllegalArgumentException
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    protected byte[] loadMAC(SecureAndroid.Mode mode, String alias) throws IOException, CryptoIOHelper.DataNotAvailableException {
        switch (mode) {
            case SHARED_PREFERENCES:
                return super.loadFromSharedPrefBase64(MAC_ALIAS, alias);
            case FILE:
                return super.readBytesFromFile(alias);
            default:
                throw new IllegalArgumentException(WRONG_MODE_EXCEPTION);
        }
    }

    /**
     * Method the check the integrity of the given ciphertext against the given MAC with
     * the given SecretKey.
     *
     * @param cipherText    The ciphertext to be checked.
     * @param mac           The Message Authentication code against which to check.
     * @param macKey        The SecretKey.
     * @return              True if check was successful, false otherwise.
     * @throws GeneralSecurityException
     */
    protected boolean checkIntegrity(byte[] cipherText, byte[] mac, SecretKey macKey) throws GeneralSecurityException {
        return Arrays.equals(mac, generateMAC(cipherText, macKey));
    }

    /**
     * Checks whether a suitable algorithm for PBKD is available.
     *
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    private void providerCheckMACCrypto() throws NoAlgorithmAvailableException {
        final LinkedList<String> algorithms = super.providerCheck();
        if (algorithms.contains("PBKDF2WithHmacSHA256")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA256";
        } else if (algorithms.contains("PBKDF2WithHmacSHA1")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
        } else {
            throw new NoAlgorithmAvailableException(NO_ALG_MSG);
        }
        if (algorithms.contains("HmacSHA256")) {
            MAC_ALGORITHM = "HmacSHA256";
        } else if (algorithms.contains("HMACSHA256")) {
            MAC_ALGORITHM = "HMACSHA256";
        } else if (algorithms.contains("HmacSHA1")) {
            MAC_ALGORITHM = "HmacSHA1";
        } else if (algorithms.contains("HMACSHA1")) {
            MAC_ALGORITHM = "HMACSHA1";
        } else {
            throw new NoAlgorithmAvailableException(NO_ALG_MSG);
        }
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     */
    private static void fixPrng() {
        if (!prng.get()) {
            synchronized (PRNGFixes.class) {
                if (!prng.get()) {
                    PRNGFixes.apply();
                    prng.set(true);
                }
            }
        }
    }
}