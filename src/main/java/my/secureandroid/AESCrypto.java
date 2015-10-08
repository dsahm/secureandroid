package my.secureandroid;

import android.content.Context;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.LinkedList;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCrypto extends my.secureandroid.CryptoIOHelper {

    // Message if no suitable algorithm available
    private static final String NO_ALG_MSG = "No algorithm available on this platform";
    // Default Instances and Modes for Encryption/Decryption
    private String AES_MODE;
    private String PBE_ALGORITHM;
    private static final String AES_INSTANCE = "AES";
    // Key lengths, iterations, salt lengths
    // private static final int AES_256 = 256;
    private static final int AES_128 = 128;
    private static final int IVECTOR_LENGTH_IN_BYTE = 16;
    private static final int PBE_ITERATIONS = 5000;
    private static final int PBE_SALT_LENGTH_BYTE = 64;
    // For Storage
    private static final String CIPHER_PART = "cipher";
    private static final String IV_PART = "iv";

    /**
     * Constructor for AESCrypto Class. Sets the context of the superclass.
     * @param context   the context
     */
    public AESCrypto(Context context) throws NoAlgorithmAvailableException {
        // Call superclass
        super(context);
        // Check availability of provoders
        providerCheckAESCrypto();
        // Apply Googles fix for the pseudo random number generator for API-Levels 16-18
        fixPrng();
        // Set AES-Mode
        AES_MODE = "AES/CBC/PKCS5Padding";
    }

    /**
     * Generates an returns an AES-Key with the specified length. If the length is neither
     * 128 nor 256 Bit, it will be set to 256 Bit.
     * @param keyLength     the desired keylength, must be 128 or 256
     * @return              the generated AES-Key
     * @throws GeneralSecurityException
     */
    public SecretKey generateRandomAESKey(int keyLength) throws GeneralSecurityException {
        if (keyLength != AES_128) {// && keyLength != AES_256) {
            keyLength = AES_128;
        }
        // Instantiante KeyGenerator
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_INSTANCE);
        // Initialize generator with the desired keylength
        keyGenerator.init(keyLength);
        // Return new key
        return keyGenerator.generateKey();
    }

    /**
     * Generates an AES-Key from the given password with the given keylength. If the keylength is
     * neither 128 nor 256 Bit, it will be set to 256 Bit.
     * @param password      the password
     * @param keyLength     the desired keylength
     * @return              the AES-Key and the salt
     * @throws GeneralSecurityException
     */
    public SaltAndKey generateRandomAESKeyFromPasswordGetSalt(char[] password, int keyLength) throws GeneralSecurityException {
        if (keyLength != AES_128) { // && keyLength != AES_256) {
            keyLength = AES_128;
        }
        // Generate random salt
        final byte [] salt = super.generateRandomBytes(PBE_SALT_LENGTH_BYTE);
        // Specifiy Key parameters
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, keyLength);
        // Load the key factory
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        // Generate random sequence for the key
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        // Return new key and salt the key was created with
        return new SaltAndKey(new SecretKeySpec(temp, AES_INSTANCE), salt);
    }

    /**
     * Generates an AES-Key from the given password with the given keylength and the given salt. If the keylength is
     * neither 128 nor 256 Bit, it will be set to 256 Bit.
     * @param password      the password
     * @param keyLength     the desired keylength
     * @param salt          the salt
     * @return              the AES-Key
     * @throws GeneralSecurityException
     */
    public SecretKey generateRandomAESKeyFromPasswordSetSalt(char[] password, byte[] salt, int keyLength) throws GeneralSecurityException {
        if (keyLength != AES_128) {// && keyLength != AES_256) {
            keyLength = AES_128;
        }
        // Specifiy Key parameters
        final KeySpec keySpec = new PBEKeySpec(password, salt , PBE_ITERATIONS, keyLength);
        // Load the key factory with the specified PBE Algorithm
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        // Generate random sequence for the key
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        // Generate and return key
        return new SecretKeySpec(temp, AES_INSTANCE);
    }


    /**
     * Encrypts a given plaintext with the given AES secret key. Also generates a random iv used for encrypting.
     * @param plainText     the text to be encrypted
     * @param secretKey     the AES key to be used for encryption
     * @return              an instance of the class CipherMacIV holding the cipher, iv and mac
     * @throws GeneralSecurityException
     */
    public CipherIV encryptAES(byte[] plainText, SecretKey secretKey) throws GeneralSecurityException {
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
        return new CipherIV(cipherText,cipher.getIV());
    }

    /**
     * Decrypts a ciphertext that was encrypted with an AES-Key and an initialization vector
     * @param cipherText    the ciphertext to be decrypted
     * @param iv            the initialization vector used for encryption
     * @param secretKey     the secret key used for encryption
     * @return              the plaintext as byte array
     * @throws GeneralSecurityException
     */
    public byte[] decryptAES(byte[] cipherText, byte[] iv, SecretKey secretKey) throws GeneralSecurityException {
        // Instantiate Cipher with the AES Instance and IvParameterSpec with the iv
        final Cipher cipher = Cipher.getInstance(AES_MODE);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Initialize cipher with the desired parameters
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        // Return plaintext
        return cipher.doFinal(cipherText);
    }

    /**
     * Saves the ciphertext and the initialization vector contained in CipherIV object
     * in two seperate files, encoded in Base64. The files are only accessible by your app.
     * @param data          the CipherIV instance
     * @param filename      the filename
     * @throws IOException
     */
    public void writeCipherAndIVToFileBase64(CipherIV data, String filename) throws IOException {
        super.saveBytesToFileBase64(filename + CIPHER_PART, data.getCipher());
        super.saveBytesToFileBase64(filename + IV_PART, data.getIv());
    }

    /**
     * Deletes the files saved under the given alias for a ciperIv object.
     * @param filename  The alias.
     */
    public void deleteCipherAndIVFile(String filename) {
        super.deleteFile(filename + CIPHER_PART);
        super.deleteFile(filename + IV_PART);
    }

    /**
     * Returns a CipherIV object containing the ciphertext and initialization vector
     * stored under the specified filename.
     * @param filename  the filename
     * @return          the CipherIV instance containing the desired cipher and iv
     * @throws IOException
     */
    public CipherIV getCipherAndIVFromFile(String filename) throws IOException {
        byte[] cipher = super.readBytesFromFileBase64(filename + CIPHER_PART);
        byte[] iv = super.readBytesFromFileBase64(filename + IV_PART);
        return new CipherIV(cipher, iv);
    }

    /**
     * Saves the ciphertext and the initialization vector contained in CipherIV object
     * in two seperate SharedPref aliases, encoded in Base64. The SharedPrefs are only accessible by
     * your app.
     * @param data        the CipherIV object
     * @param spAlias     the alias for the SharedPref
     * @param cipherIvAlias the alias for the ciphertext and iv
     */
    public void saveCipherAndIVToSharedPrefBase64(CipherIV data, String spAlias, String cipherIvAlias) {
        super.saveToSharedPrefBase64(spAlias, cipherIvAlias + CIPHER_PART, data.getCipher());
        super.saveToSharedPrefBase64(spAlias, cipherIvAlias + IV_PART, data.getIv());
    }

    /**
     * Deletes the submitted cipherIv object from the SharedPref submitted under spAlias.
     * @param spAlias           The alias for the Shared Pref.
     * @param cipherIvAlias     The alias for the cipherIv object.
     */
    public void deleteCipherAndIVFromSharedPref(String spAlias, String cipherIvAlias) {
        super.deleteFromSharedPref(spAlias, cipherIvAlias + CIPHER_PART);
        super.deleteFromSharedPref(spAlias, cipherIvAlias+ IV_PART);
    }

    /**
     * Returns a CipherIV object containing the ciphertext and initialization vector
     * stored under the specified alias.
     * @param spAlias     the alias for the SharedPref
     * @param ciphIVAlias the alias for the ciphertext and iv
     * @return            the CipherIV instance containing the desired cipher and iv
     * @throws my.secureandroid.CryptoIOHelper.DataNotAvailableException
     */
    public CipherIV getCipherAndIVFromSharedPref(String spAlias, String ciphIVAlias) throws DataNotAvailableException {
        byte[] cipher = super.loadFromSharedPrefBase64(spAlias, ciphIVAlias + CIPHER_PART);
        byte[] iv = super.loadFromSharedPrefBase64(spAlias, ciphIVAlias + IV_PART);
        return new CipherIV(cipher, iv);
    }

    /**
     * Method to check whether the desire algorithms are provided on the phone. Sets the best automatically.
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
     * Will only run once, and every subsequent call should return immediately.
     */
    private static void fixPrng() {
        synchronized (PRNGFixes.class) {
            PRNGFixes.apply();
        }
    }

    /**
     * Class to hold a Ciphertext and an Initialization Vector.
     */
    public class CipherIV {

        private byte[] cipher, iv;

        public CipherIV (byte[] cipher, byte[] iv) {
            this.cipher = cipher;
            this.iv = iv;
        }

        public byte [] getCipher() {
            return cipher;
        }
        public byte[] getIv() {
            return iv;
        }
    }

    /**
     * Returns a CipherIV instance.
     * @param cipher    The cipher.
     * @param iv        The iv.
     * @return          The CipherIV instance.
     */
    public CipherIV instantiateCipherIV (byte[] cipher, byte[] iv) {
        return new CipherIV(cipher, iv);
    }

    // Bisher nicht benötigt
    /**
     * Generates an AES-Key from the given password with the given kelength. If the keylength is
     * neither 128 nor 256 Bit, it will be set to 256 Bit.
     * @param password      the password
     * @param keyLength     the desired keylength
     * @return              the AES-Key
     * @throws GeneralSecurityException
     */
    public SecretKey generateRandomAESKeyFromPassword(char[] password, int keyLength) throws GeneralSecurityException {
        if (keyLength != AES_128) {// && keyLength != AES_256) {
            keyLength = AES_128;
        }
        final KeySpec keySpec = new PBEKeySpec(password, super.generateRandomBytes(PBE_SALT_LENGTH_BYTE), PBE_ITERATIONS, keyLength);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(temp, AES_INSTANCE);
    }

    /**
     * Stores the given secret key into the specified file, encoded to Base64.
     * The file is only accessible by your app.
     * @param secretKey     the secret key to be stored
     * @param filename      the filename to store the secret key in
     * @throws IOException
     */
    public void storeAESKeyToFileBase64(SecretKey secretKey, String filename) throws IOException {
        super.saveBytesToFileBase64(filename, secretKey.getEncoded());
    }

    /**
     * Retrieves and returns the formerly Base64-encoded AES-Key saved under the specified file.
     * @param filename      the filename the secret key was stored in
     * @return              the AES-Key
     * @throws IOException
     */
    public SecretKey getAESKeyFromFileBase64(String filename) throws IOException {
        byte[] temp = super.readBytesFromFileBase64(filename);
        return new SecretKeySpec(temp, 0, temp.length, AES_INSTANCE);
    }

    /**
     * Stores the given secret key into the apps shared preferences, encoded to Base64.
     * The SharedPreferences are only accessible by your app.
     * @param spAlias       the alias of the SharedPref
     * @param keyAlias      the alias under which the key is to be stored in the SharedPrefs
     * @param secretKey     the secret key to be stored
     */
    public void storeAESKeyInSharedPrefBase64(String spAlias, String keyAlias, SecretKey secretKey) {
        super.saveToSharedPrefBase64(spAlias, keyAlias, secretKey.getEncoded());
    }

    /**
     * Retrieves and returns the formerly Base64-encoded AES-Key saved under the specified SharedPrefs.
     * @param spAlias       the alias of the Shared Preferences
     * @param keyAlias      the alias of the key
     * @return              the AES-Key
     * @throws my.secureandroid.CryptoIOHelper.DataNotAvailableException
     */
    public SecretKey getAESKeyFromSharedPrefBase64(String spAlias, String keyAlias) throws CryptoIOHelper.DataNotAvailableException {
        byte[] temp = super.loadFromSharedPrefBase64(spAlias, keyAlias);
        return new SecretKeySpec(temp, 0, temp.length, AES_INSTANCE);
    }
}
