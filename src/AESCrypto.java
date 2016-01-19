package my.secureandroid;

import android.content.Context;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class that implements cryptographic AES-operations.
 */

public class AESCrypto extends CryptoIOHelper {

    // Message if no suitable algorithm available
    private static final String NO_ALG_MSG = "No algorithm available on this platform";
    // Default Instances and Modes for Encryption/Decryption
    private String AES_MODE = "AES/CBC/PKCS5Padding";
    private String PBE_ALGORITHM;
    private static final String AES_INSTANCE = "AES";
    // Key lengths, iterations, salt lengths
    private static final int AES_128 = 128;
    private static final int IVECTOR_LENGTH_IN_BYTE = 16;
    private static int PBE_ITERATIONS;
    private static final int PBE_SALT_LENGTH_BYTE = 64;
    // For Storage
    private static final String CIPHER_PART = "cipher";
    private static final String IV_PART = "iv";
    // Exception messages
    private static final String WRONG_INTEGRITY_MODE = "Bad Padding. Some possible reasons: Wrong integrity mode or changed "+
            "password without decrypting data first and then re-encrypting it";
    // For PRNG-Fix
    private static AtomicBoolean prng;

    /**
     * Constructor for AESCrypto Class. Sets the context of the superclass.
     *
     * @param context   The context.
     * @param iterations The iteration count for the PBKDF.
     * @throws NoAlgorithmAvailableException
     */
    protected AESCrypto(Context context, int iterations) throws NoAlgorithmAvailableException {
        // Call superclass
        super(context);
        // Check availability of provoders
        providerCheckAESCrypto();
        // Apply Googles fix for the pseudo random number generator for API-Levels 16-18
        prng = new AtomicBoolean(false);
        fixPrng();
        // set the iteration count
        PBE_ITERATIONS = iterations;
    }

    /**
     * Generates an returns an 128 Bit long AES-Key.
     *
     * @return The generated AES-Key.
     * @throws GeneralSecurityException
     */
    protected SecretKey generateRandomAESKey() throws GeneralSecurityException {
        fixPrng();
        // Instantiante KeyGenerator
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_INSTANCE);
        // Initialize generator with the desired keylength
        keyGenerator.init(AES_128);
        // Return new key
        return keyGenerator.generateKey();
    }

    /**
     * Generates an 128 Bit long AES-Key from the given password.
     *
     * @param password      The password.
     * @return              The AES-Key and the salt.
     * @throws GeneralSecurityException
     */
    protected SaltAndKey generateRandomAESKeyFromPasswordGetSalt(char[] password) throws GeneralSecurityException {
        fixPrng();
        // Generate random salt
        final byte [] salt = super.generateRandomBytes(PBE_SALT_LENGTH_BYTE);
        // Specifiy Key parameters
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, AES_128);
        // Load the key factory
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        // Generate random sequence for the key
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        // Return new key and salt the key was created with
        return new SaltAndKey(new SecretKeySpec(temp, AES_INSTANCE), salt);
    }

    /**
     * Generates an 128 Bit long AES-Key from the given password with the given salt.
     *
     * @param password      The password.
     * @param salt          The salt.
     * @return              The AES-Key.
     * @throws GeneralSecurityException
     */
    protected SecretKey generateAESKeyFromPasswordSetSalt(char[] password, byte[] salt) throws GeneralSecurityException {
        fixPrng();
        // Specifiy Key parameters
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, AES_128);
        // Load the key factory with the specified PBE Algorithm
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        // Generate random sequence for the key
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        // Generate and return key
        return new SecretKeySpec(temp, AES_INSTANCE);
    }

    /**
     * Encrypts a given plaintext with the given AES secret key. Also generates a random iv used for encrypting.
     *
     * @param plainText     The text to be encrypted.
     * @param secretKey     The AES key to be used for encryption.
     * @return              An instance of the class CipherIV holding the cipher and iv.
     * @throws GeneralSecurityException
     */
    protected CipherIV encryptAES(byte[] plainText, SecretKey secretKey) throws GeneralSecurityException {
        fixPrng();
        // Instantiate Cipher with the AES Instance
        final Cipher cipher = Cipher.getInstance(AES_MODE);
        // Generate random bytes for the initialization vector
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] initVector = new byte[IVECTOR_LENGTH_IN_BYTE];
        secureRandom.nextBytes(initVector);
        final IvParameterSpec initVectorParams = new IvParameterSpec(initVector);
        // Initialize cipher object with the desired parameters
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVectorParams);
        // Encrypt
        byte[] cipherText = cipher.doFinal(plainText);
        // Return ciphertext and iv in CipherIV object
        return new CipherIV(cipherText, cipher.getIV());
    }

    /**
     * Decrypts a ciphertext that was encrypted with an AES-Key and an initialization vector.
     *
     * @param cipherText    The ciphertext to be decrypted.
     * @param iv            The initialization vector used for encryption.
     * @param secretKey     The secret key used for encryption.
     * @return              The plaintext as byte array.
     * @throws GeneralSecurityException
     */
    protected byte[] decryptAES(byte[] cipherText, byte[] iv, SecretKey secretKey) throws GeneralSecurityException {
        // Instantiate Cipher with the AES Instance and IvParameterSpec with the iv
        final Cipher cipher = Cipher.getInstance(AES_MODE);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Initialize cipher with the desired parameters
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        // Return plaintext
        try {
            return cipher.doFinal(cipherText);
        } catch (BadPaddingException e) {
            throw new BadPaddingException(WRONG_INTEGRITY_MODE);
        }
    }

    /**
     * Saves the ciphertext and the initialization vector contained in CipherIV object
     * in two seperate files, encoded in Base64. The files are only accessible by your app.
     *
     * @param data          The CipherIV instance.
     * @param filename      The filename.
     * @throws IOException
     */
    protected void writeCipherAndIVToFileBase64(CipherIV data, String filename) throws IOException {
        super.saveBytesToFileBase64(filename + CIPHER_PART, data.getCipher());
        super.saveBytesToFileBase64(filename + IV_PART, data.getIv());
    }

    /**
     * Deletes the files saved under the given alias for a ciperIv object.
     *
     * @param filename  The alias.
     * @throws CryptoIOHelper.DataNotAvailableException
     *
     */
    protected void deleteCipherAndIVFile(String filename) throws DataNotAvailableException {
        super.deleteFile(filename + CIPHER_PART);
        super.deleteFile(filename + IV_PART);
    }

    /**
     * Returns a CipherIV object containing the ciphertext and initialization vector
     * stored under the specified filename.
     *
     * @param filename  The filename.
     * @return          The CipherIV instance containing the desired cipher and iv.
     * @throws IOException
     */
    protected CipherIV getCipherAndIVFromFile(String filename) throws IOException {
        byte[] cipher = super.readBytesFromFile(filename + CIPHER_PART);
        byte[] iv = super.readBytesFromFile(filename + IV_PART);
        return new CipherIV(cipher, iv);
    }

    /**
     * Saves the ciphertext and the initialization vector contained in CipherIV object
     * in two seperate SharedPref aliases, encoded in Base64. The SharedPrefs are only accessible by
     * your app.
     *
     * @param data        The CipherIV object.
     * @param spAlias     The alias for the SharedPref.
     * @param cipherIvAlias The alias for the ciphertext and iv.
     */
    protected void saveCipherAndIVToSharedPrefBase64(CipherIV data, String spAlias, String cipherIvAlias) {
        super.saveToSharedPrefBase64(spAlias, cipherIvAlias + CIPHER_PART, data.getCipher());
        super.saveToSharedPrefBase64(spAlias, cipherIvAlias + IV_PART, data.getIv());
    }

    /**
     * Deletes the submitted cipherIv object from the SharedPref submitted under spAlias.
     *
     * @param spAlias           The alias for the Shared Pref.
     * @param cipherIvAlias     The alias for the cipherIv object.
     */
    protected void deleteCipherAndIVFromSharedPref(String spAlias, String cipherIvAlias) {
        super.deleteFromSharedPref(spAlias, cipherIvAlias + CIPHER_PART);
        super.deleteFromSharedPref(spAlias, cipherIvAlias+ IV_PART);
    }

    /**
     * Returns a CipherIV object containing the ciphertext and initialization vector
     * stored under the specified alias.
     *
     * @param spAlias     The alias for the SharedPref.
     * @param ciphIVAlias The alias for the ciphertext and iv.
     * @return            The CipherIV instance containing the desired cipher and iv.
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    protected CipherIV getCipherAndIVFromSharedPref(String spAlias, String ciphIVAlias) throws DataNotAvailableException {
        byte[] cipher = super.loadFromSharedPrefBase64(spAlias, ciphIVAlias + CIPHER_PART);
        byte[] iv = super.loadFromSharedPrefBase64(spAlias, ciphIVAlias + IV_PART);
        return new CipherIV(cipher, iv);
    }

    /**
     * Class to hold a Ciphertext and an Initialization Vector.
     */
    protected class CipherIV {

        private byte[] cipher, iv;

        protected CipherIV (byte[] cipher, byte[] iv) {
            this.cipher = cipher;
            this.iv = iv;
        }

        protected byte [] getCipher() {
            return cipher;
        }
        protected byte[] getIv() {
            return iv;
        }
    }

    /**
     * Returns a CipherIV instance.
     *
     * @param cipher    The cipher.
     * @param iv        The iv.
     * @return          The CipherIV instance.
     */
    protected CipherIV instantiateCipherIV (byte[] cipher, byte[] iv) {
        return new CipherIV(cipher, iv);
    }

    /**
     * Method to check which algorithms are available on the current phone. Sets the best automatically.
     *
     * @throws NoAlgorithmAvailableException
     */
    private void providerCheckAESCrypto() throws NoAlgorithmAvailableException {
        final LinkedList<String> algorithms = super.providerCheck();
        if (algorithms.contains("PBKDF2WithHmacSHA256")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA256";
        } else if (algorithms.contains("PBKDF2WithHmacSHA1")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
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
