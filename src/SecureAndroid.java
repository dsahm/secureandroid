package my.secureandroid;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Daniel Sahm on 23.09.15.
 */

public class SecureAndroid {

    // Needed constants
    private static final String AES_MASTERKEY_SALT_ALIAS = "SecureAndroid.AES.Master.salt.alias";
    private static final String AES_INTERMEDIATEKEY_ALIAS = "SecureAndroid.AES.Intermediate.alias";
    private static final String PASSWORD_SALT_ALIAS = "SecureAndroid.Password.salt.alias";
    private static final String PASSWORD_HASH_ALIAS = "SecureAndroid.Password.hash.alias";
    private static final String KEY_DATA_ALIAS = "SecureAndroid.Key.Data.alias";
    private static final String CIPHER_IV_ALIAS = "SecureAndroid.CipherIV.alias";
    private static final String MAC_INTERMEDIATE_KEY_ALIAS = "SecureAndroid.MacKey.Alias";
    private static final String MAC_USER_ALIAS = "SecureAndroid.MacIv.Alias";
    private static final String MAC_MASTER_KEY_SALT_ALIAS = "SecureAndroid.MacSalt.alias";
    private static final String AES_INTERMEDIATE_KEY_MAC_ALIAS = "SecureAndroid.Aes.Master.Mac.alias";
    private static final String MAC_INTERMEDIATE_KEY_MAC_ALIAS = "SecureAndroid.Mac.Imediate.Mac.alias";
    private static final String ITERATION_COUNT_ALIAS = "SecureAndroid.IterationCount.alias";
    private static final String PASSWORD_ALIAS = "SecureAndroid.Password.Alias";
    private static final String IMEDIATE_KEY_DATA = "SecureAndoird.Intermediate.Key.Data";
    private static final String NO_ALG_MSG = "No suitable algorithm available on this platform";
    private static final String NO_KEYMATERIAL_MSG = "No keymaterial found: Nothing encrypted before or wrong" +
            "integrity mode?";
    private static final String AES = "AES";
    private static final String MAC = "MAC";
    private static final int IV_LENGTH_BYTE = 16;
    private static int MAC_LENGTH_BYTE;
    private static int MACPLUSIV_LENGTH_BYTE;
    private static final int ITERATION_FACTOR = 3;
    private static final int ITERATION_MIDDLE = 10000;
    public static final int SHARED_PREFERENCES = 0;
    public static final int INTEGRITY = 1;
    public static final int NO_INTEGRITY = 0;
    public static final int FILE = 1;

    // Exception Messages
    private static final String WRONG_PASSWORD = "The provided password was wrong";
    private static final String WRONG_MODE_EXCEPTION = "Wrong mode, choose SecureAndroid.FILE or SecureAndroid.SHARED_PREFERENCES";
    private static final String WRONG_INTEGRITY_MODE_EXCEPTION = "Wrong integrity mode, choose SecureAndroid.INTEGRITY or Secure" +
            "Android.NO_INTEGRITY";
    private static final String INTEGRITY_CHECK_FAILED = "The integrity check of the data failed, will not continue to decrypt";

    // Needed objects
    private AESCrypto aesCrypto;
    private PasswordCrypto passwordCrypto;
    private MACCrypto macCrypto;
    private CryptoIOHelper cryptoIOHelper;

    /**
     * Constructor.
     * @param context The context.
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    public SecureAndroid(Context context, int minIteratons) throws CryptoIOHelper.NoAlgorithmAvailableException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Instantiate CryptoIOHelper
        cryptoIOHelper = new CryptoIOHelper(context);
        // Prepare iterations
        int iterations;
        // See if performane-test already made and load iterations
        try {
            iterations = Integer.parseInt(new String(cryptoIOHelper.loadFromSharedPrefBase64(ITERATION_COUNT_ALIAS, ITERATION_COUNT_ALIAS)));
//            Log.i("SAVED ITERATION COUNT", String.valueOf(iterations));
        } catch (CryptoIOHelper.DataNotAvailableException e) {
            // If not, do performance-test
            // Get the suitable iteration count for good performance and security
            iterations = (int)(cryptoIOHelper.hashPerformanceTest(ITERATION_MIDDLE, minIteratons))/ITERATION_FACTOR;
            // Save the iteration count
            cryptoIOHelper.saveToSharedPrefBase64(ITERATION_COUNT_ALIAS, ITERATION_COUNT_ALIAS, String.valueOf(iterations).getBytes());
//            Log.i("LOADED ITERATION COUNT", String.valueOf(iterations));
        }
        // Instantiate Crypto-classes
        aesCrypto = new AESCrypto(context, iterations);
        passwordCrypto = new PasswordCrypto(context, iterations);
        macCrypto = new MACCrypto(context, iterations);
        // Check and define the MAC length according to the availability of SHA256/1 on the platform
        checkMacLength();
        MACPLUSIV_LENGTH_BYTE = IV_LENGTH_BYTE+MAC_LENGTH_BYTE;
    }

    /**
     * Encrypts the given byte [] plaintext and returns the ciphertext as byte [].
     * @param plaintext The plaintext as byte array.
     * @return          The ciphertext as byte array.
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.WrongPasswordException
     */
    public byte[] encrypt(int integrity, byte[] plaintext) throws CryptoIOHelper.NoKeyMaterialException, CryptoIOHelper.WrongModeException, 
        CryptoIOHelper.IntegrityCheckFailedException, GeneralSecurityException, CryptoIOHelper.WrongPasswordException, CryptoIOHelper.DataNotAvailableException {
        return encrypt(integrity, plaintext, getAutoPassword().toCharArray());
    }

    /**
     * Decrypts the given byte [] ciphertxt and returns the plaintext as byte [].
     * @param ciphertext    The ciphertext as byte array.
     * @return              The plaintext as byte array.
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    public byte[] decrypt(int integrity, byte[] ciphertext) throws CryptoIOHelper.WrongModeException,
            CryptoIOHelper.NoKeyMaterialException, GeneralSecurityException, CryptoIOHelper.WrongPasswordException, CryptoIOHelper.DataNotAvailableException,
            CryptoIOHelper.IntegrityCheckFailedException {
        return decrypt(integrity, ciphertext, getAutoPassword().toCharArray());
    }

    /**
     * Encrypts the given byte [] plaintext with a key derived from the provided
     * password and returns the ciphertext as byte [].
     * @param plaintext The plaintext as byte array.
     * @param password  The desired password that will be used to derive the encryption key.
     * @return          The ciphertext as byte array.
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    public byte[] encryptWithPassword(int integrity, byte[] plaintext, char[] password) throws CryptoIOHelper.NoKeyMaterialException,
            CryptoIOHelper.WrongModeException, CryptoIOHelper.IntegrityCheckFailedException, GeneralSecurityException, CryptoIOHelper.WrongPasswordException, 
            CryptoIOHelper.DataNotAvailableException {
        return encrypt(integrity, plaintext, password);
    }

    /**
     * Decrypts the given byte [] ciphertext with a key derived from the provided
     * password and returns the plaintext as byte [].
     * @param ciphertext    The ciphertext as byte array.
     * @param password      The desired password that will be used to derive the decryption key.
     * @return              The plaintext as byte array.
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    public byte[] decryptWithPassword(int integrity, byte[] ciphertext, char[] password) throws CryptoIOHelper.NoKeyMaterialException, CryptoIOHelper.WrongModeException,
            CryptoIOHelper.DataNotAvailableException, CryptoIOHelper.WrongPasswordException,
            GeneralSecurityException, CryptoIOHelper.IntegrityCheckFailedException {
        return decrypt(integrity, ciphertext, password);
    }


    /**
     * Encrypts the given plaintext and stores it on the device under the provided alias.
     * @param mode          The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
     * @param plaintext     The plaintext as byte array.
     * @param alias         The alias under which the data will be stored.
     * @throws IOException
     * @throws CryptoIOHelper.WrongModeException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    public void encryptAndStore(int integrity, int mode, byte[] plaintext, String alias) throws CryptoIOHelper.NoKeyMaterialException,
        CryptoIOHelper.IntegrityCheckFailedException, IOException, CryptoIOHelper.WrongModeException, CryptoIOHelper.WrongPasswordException, 
        GeneralSecurityException, CryptoIOHelper.DataNotAvailableException {
        if (integrity == INTEGRITY) {
            // Save the encrypted data under the given alias
            saveUserCipherMacIv(mode, encrypt(integrity, plaintext, getAutoPassword().toCharArray()), alias);
        } else if (integrity == NO_INTEGRITY) {
            saveUserCipherIv(mode, encrypt(integrity, plaintext, getAutoPassword().toCharArray()), alias);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_INTEGRITY_MODE_EXCEPTION);
        }
    }


    /**
     * Encrypts the given plaintext and stores it on the device under the provided alias with
     * a key derived from the provided password.
     * @param integrity     The integrity mode. SecureAndroid.INTEGRITY and SecureAndroid.NO_INTEGRITY are possible.
     * @param mode          The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
     * @param plaintext     The plaintext as byte array.
     * @param alias         The alias under which the data will be stored.
     * @param password      The password that will be used to derive the decryption key.
     * @throws CryptoIOHelper.WrongModeException
     * @throws IOException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    public void encryptAndStoreWithPassword(int integrity, int mode, byte[] plaintext, String alias, char[] password) throws CryptoIOHelper.NoKeyMaterialException,
            CryptoIOHelper.IntegrityCheckFailedException, CryptoIOHelper.WrongModeException, IOException, CryptoIOHelper.WrongPasswordException, GeneralSecurityException,
            CryptoIOHelper.DataNotAvailableException {
        if (integrity == SecureAndroid.INTEGRITY) {
            // Save the encrypted data under the given alias
            saveUserCipherMacIv(mode, encrypt(integrity, plaintext, password), alias);
        } else if (integrity == SecureAndroid.NO_INTEGRITY) {
            // Save the encrypted data under the given alias
            saveUserCipherIv(mode, encrypt(integrity, plaintext, password), alias);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_INTEGRITY_MODE_EXCEPTION);
        }

    }

    /**
     * Retrieves and decrypts data stored under the provided alias.
     * @param mode      The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
     * @param alias     The alias the data was stored under.
     * @return          The plaintext as byte array.
     * @throws CryptoIOHelper.WrongModeException
     * @throws IOException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    public byte[] retrieve(int integrity, int mode, String alias) throws CryptoIOHelper.NoKeyMaterialException, CryptoIOHelper.IntegrityCheckFailedException, 
        CryptoIOHelper.WrongModeException, IOException, CryptoIOHelper.WrongPasswordException, GeneralSecurityException, CryptoIOHelper.DataNotAvailableException {
        return retrieve(integrity, mode, alias, getAutoPassword().toCharArray());
    }

    /**
     * Retrieves and decrypts data stored under the provided alias.
     * @param mode      The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
     * @param alias     The alias the data was stored under.
     * @param password  The password that was used for storage.
     * @return          The plaintext as byte array.
     * @throws CryptoIOHelper.WrongModeException
     * @throws IOException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    public byte[] retrieveWithPassword(int integrity, int mode, String alias, char[] password) throws CryptoIOHelper.NoKeyMaterialException, 
        CryptoIOHelper.IntegrityCheckFailedException, IOException, CryptoIOHelper.WrongPasswordException, CryptoIOHelper.DataNotAvailableException, CryptoIOHelper.WrongModeException, GeneralSecurityException {
        return retrieve(integrity, mode, alias, password);
    }


    /**
     * Deletes either the SharedPrefs alias entry or the file saved under the alias.
     * @param mode      The mode, use SecureAndroid.SHARED_PREFERENCES or SecureAndroid.FILE.
     * @param alias     The alias of the SharedPref entry or the filename.
     * @throws CryptoIOHelper.WrongModeException
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    public void deleteData (int mode, String alias) throws CryptoIOHelper.WrongModeException, CryptoIOHelper.DataNotAvailableException {
        if (mode == SHARED_PREFERENCES) {
            aesCrypto.deleteCipherAndIVFromSharedPref(CIPHER_IV_ALIAS, alias);
        } else if (mode == FILE) {
            aesCrypto.deleteCipherAndIVFile(alias);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_MODE_EXCEPTION);
        }
    }

    /**
     * Wipes the intermediate key and thus destroys all formerly encrypted data in the sense
     * of it being irrecoverable.
     */
    public void wipeKey()  {
        // For production
        cryptoIOHelper.deleteSharedPref(IMEDIATE_KEY_DATA);
        cryptoIOHelper.deleteSharedPref(PASSWORD_ALIAS);
    }

    /**
     * Private method that handles the encryption process.
     * @param plaintext     The plaintext as byte array.
     * @param password      The password that will be used to derive the encryption key.
     * @return              The ciphertext as byte array.
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    private byte[] encrypt(int integrity, byte[] plaintext, char[] password) throws CryptoIOHelper.NoKeyMaterialException, CryptoIOHelper.WrongModeException, 
        CryptoIOHelper.IntegrityCheckFailedException, GeneralSecurityException, CryptoIOHelper.WrongPasswordException, CryptoIOHelper.DataNotAvailableException {
        AESCrypto.CipherIV cipherIv;
        try {
            if (integrity == INTEGRITY) {
                // Try to load formerly stored key data and use the data to encrypt plaintext
                SecretKeys secretKeys = getKeyData(password);
                cipherIv = aesCrypto.encryptAES(plaintext, secretKeys.getAesKey());
                final byte[] mac = macCrypto.generateMac(cipherIv.getCipher(), secretKeys.getMacKey());
                return concatenateIvAndCipherAndMac(cipherIv, mac);
            } else if (integrity == NO_INTEGRITY) {
                // Try to load formerly stored key data and use the data to encrypt plaintext
                SecretKey secretKey = getKeyDataWithoutMac(password);
                cipherIv = aesCrypto.encryptAES(plaintext, secretKey);
                return concatenateIvAndCipher(cipherIv);
            } else {
                throw new CryptoIOHelper.WrongModeException(WRONG_INTEGRITY_MODE_EXCEPTION);
            }
        }
        catch (CryptoIOHelper.NoKeyMaterialException e) {
            // If no key data was stored, create and store key data und use the stored key data to encrypt plaintext
            if (integrity == INTEGRITY) {
                SecretKeys secretKeys = createAndStoreAndGetKeyData(password);
                cipherIv = aesCrypto.encryptAES(plaintext, secretKeys.getAesKey());
                final byte[] mac = macCrypto.generateMac(cipherIv.getCipher(), secretKeys.getMacKey());
                return concatenateIvAndCipherAndMac(cipherIv, mac);
            } else if (integrity == NO_INTEGRITY) {
                SecretKey secretKey = createAndStoreAndGetKeyDataWithoutMac(password);
                cipherIv = aesCrypto.encryptAES(plaintext, secretKey);
                return concatenateIvAndCipher(cipherIv);
            } else {
                throw new CryptoIOHelper.WrongModeException(WRONG_INTEGRITY_MODE_EXCEPTION);
            }
        }
    }

    /**
     * Private method that handles the decryption process.
     * @param ivAndCipherAndMac      The ciphertext including the iv and the mac.
     * @param password         The password that will be used to derive the decryption key.
     * @return                 The plaintext as byte array.
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    private byte[] decrypt(int integrity, byte[] ivAndCipherAndMac, char[] password) throws CryptoIOHelper.WrongModeException, 
        CryptoIOHelper.NoKeyMaterialException, CryptoIOHelper.IntegrityCheckFailedException, GeneralSecurityException, CryptoIOHelper.WrongPasswordException, CryptoIOHelper.DataNotAvailableException {
        // Decode the ciphertext
        final byte[] innerTempArray = cryptoIOHelper.decodeBase64(ivAndCipherAndMac);
        byte [] iv = new byte[IV_LENGTH_BYTE];
        if (integrity == INTEGRITY) {
            final byte[] mac = new byte[MAC_LENGTH_BYTE];
            final byte[] cipher = new byte[innerTempArray.length - (IV_LENGTH_BYTE+MAC_LENGTH_BYTE)];
            disassembleIvAndCipherAndMac(iv, mac, cipher, innerTempArray);
            // Get the keys for integrity checking and decryption
            final SecretKeys secretKeys = getKeyData(password);
            if (macCrypto.checkIntegrity(cipher, mac, secretKeys.getMacKey())) {
                // if integrity check was successful, return the decrypted plaintext as byte array
                return aesCrypto.decryptAES(cipher, iv, secretKeys.getAesKey());
            } else {
                throw new CryptoIOHelper.IntegrityCheckFailedException(INTEGRITY_CHECK_FAILED);
            }
        } else if (integrity == NO_INTEGRITY) {
            final byte[] cipher = new byte[innerTempArray.length - IV_LENGTH_BYTE];
            disassembleIvAndCipher(iv, cipher, innerTempArray);
            // Get the keys for integrity checking and decryption
            final SecretKey secretKey = getKeyDataWithoutMac(password);
            return aesCrypto.decryptAES(cipher, iv, secretKey);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_INTEGRITY_MODE_EXCEPTION);
        }

    }

    /**
     * Private method that returns the data stored under the provided password and alias.
     * @param mode      The storage mode.
     * @param alias     The alias.
     * @param password  The password.
     * @return          The decrypted data.
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.NoKeyMaterialException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws CryptoIOHelper.WrongModeException
     * @throws IOException
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    private byte[] retrieve(int integrity, int mode, String alias, char[] password) throws GeneralSecurityException, CryptoIOHelper.NoKeyMaterialException, 
            CryptoIOHelper.IntegrityCheckFailedException, CryptoIOHelper.WrongPasswordException, CryptoIOHelper.WrongModeException, IOException, 
            CryptoIOHelper.DataNotAvailableException {
        AESCrypto.CipherIV cipherIV;
        if (integrity == INTEGRITY) {
            SecretKeys secretKeys = getKeyData(password);
            cipherIV = getUserCipherIv(mode, alias);
            final byte[] mac = macCrypto.loadMAC(mode, alias);
            if (macCrypto.checkIntegrity(cipherIV.getCipher(), mac, secretKeys.getMacKey())) {
                return aesCrypto.decryptAES(cipherIV.getCipher(), cipherIV.getIv(), secretKeys.getAesKey());
            } else {
                throw new CryptoIOHelper.IntegrityCheckFailedException(INTEGRITY_CHECK_FAILED);
            }
        } else if (integrity == NO_INTEGRITY) {
            SecretKey secretKey = getKeyDataWithoutMac(password);
            cipherIV = getUserCipherIv(mode, alias);
            return aesCrypto.decryptAES(cipherIV.getCipher(), cipherIV.getIv(), secretKey);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_INTEGRITY_MODE_EXCEPTION);
        }
    }

    /**
     * Method the disassemble the concatenated CipherIvMac-Array.
     * @param iv        The initialized but empty iv array.
     * @param mac       The initialized but empty mac array.
     * @param cipher    The initialized but empty mac array.
     * @param ivAndCipherAndMac The ivAndCipherAndMac array.
     */
    private void disassembleIvAndCipherAndMac(byte[] iv, byte[] mac, byte[] cipher, byte[] ivAndCipherAndMac) {
        // Copy the first 128 Bit of ivAndCipherAndMac into iv, these contain the iv
        System.arraycopy(ivAndCipherAndMac, 0, iv, 0, IV_LENGTH_BYTE);
        // Copy Bit 129-385/289 of ivAndCipherAndMac into mac, these contain the mac
        System.arraycopy(ivAndCipherAndMac, IV_LENGTH_BYTE, mac, 0, MAC_LENGTH_BYTE);
        // Copy the remaining Bits into cipher
        System.arraycopy(ivAndCipherAndMac, MACPLUSIV_LENGTH_BYTE, cipher, 0, cipher.length);
    }

    /**
     * Method the disassemble the concatenated CipherIv-Array.
     * @param iv        The initialized but empty iv array.
     * @param cipher    The initialized but empty mac array.
     * @param ivAndCipher The ivAndCipherAndMac array.
     */
    private void disassembleIvAndCipher(byte[] iv, byte[] cipher, byte[] ivAndCipher) {
        // Copy the first 128 Bit of ivAndCipher into iv, these contain the iv
        System.arraycopy(ivAndCipher, 0, iv, 0, IV_LENGTH_BYTE);
        // Copy the cipher part into cipher
        System.arraycopy(ivAndCipher, IV_LENGTH_BYTE, cipher, 0, cipher.length);

    }

    /**
     * Method that returns the auto-generated password if it is needed for decrypting data on
     * another device. The password is device-dependend. CAUTION: You must encrypt the password
     * before you send it over any network AND/OR use strong traffic encryption+authentication.
     * @return      The password.
     */
    private String getAutoPassword() {
        return cryptoIOHelper.getUniquePsuedoID();
    }

    /**
     * Private method that concatenates three byte arrays.
     * @param cipherIv  The cipherIv object that holds the seperate ciphertext und iv arrays.
     * @param mac       The message authentication code corresponding to the cipherIv object.
     * @return          One byte array where the iv and the ciphertext are concatenated.
     */
    private byte[] concatenateIvAndCipherAndMac(AESCrypto.CipherIV cipherIv, byte[] mac) {
        // Create necessary arrays
        final byte[] iv = cipherIv.getIv();
        final byte[] cipher = cipherIv.getCipher();
        final byte[] ivAndCipherAndMac = new byte[IV_LENGTH_BYTE + MAC_LENGTH_BYTE + cipher.length];
        // Copy the iv into the first 128 Bit of the new array
        System.arraycopy(iv, 0, ivAndCipherAndMac, 0, IV_LENGTH_BYTE);
        // Copy the mac into the next 160/256 Bit of the new array
        System.arraycopy(mac, 0, ivAndCipherAndMac, IV_LENGTH_BYTE, MAC_LENGTH_BYTE);
        // Append the cipher at the end
        System.arraycopy(cipher, 0, ivAndCipherAndMac, MACPLUSIV_LENGTH_BYTE, cipher.length);
        // Return the array containing iv+mac+cipher
        return cryptoIOHelper.encodeToBase64(ivAndCipherAndMac);
    }

    /**
     * Private method that concatenates two byte arrays.
     * @param cipherIv  The cipherIv object that holds the seperate ciphertext und iv arrays.
     * @return          One byte array where the iv and the ciphertext are concatenated.
     */
    private byte[] concatenateIvAndCipher(AESCrypto.CipherIV cipherIv) {
        // Create necessary arrays
        final byte[] iv = cipherIv.getIv();
        final byte[] cipher = cipherIv.getCipher();
        final byte[] ivAndCipher = new byte[IV_LENGTH_BYTE + cipher.length];
        // Copy the iv into the first 128 Bit of the new array
        System.arraycopy(iv, 0, ivAndCipher, 0, IV_LENGTH_BYTE);
        // Append the cipher at the end
        System.arraycopy(cipher, 0, ivAndCipher, IV_LENGTH_BYTE, cipher.length);
        // Return the array containing iv+mac+cipher
        return cryptoIOHelper.encodeToBase64(ivAndCipher);
    }

    /**
     * Private method that creates the AES and MAC master-keys and stores its salt values. Then the intermediate keys
     * are generated and stored in the SharedPreferences. The key then is loaded and returned to the caller.
     * @param password      The password from which the master key will be derived.
     * @return              The AES and MAC intermediate-keys used for data encryption, decryption and integrity checking.
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.DataNotAvailableException 
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    private SecretKeys createAndStoreAndGetKeyData(char[] password) throws GeneralSecurityException, CryptoIOHelper.DataNotAvailableException, 
        CryptoIOHelper.IntegrityCheckFailedException {
        // Hash the password with salt and get the hashed password and the salt
        final PasswordCrypto.HashedPasswordAndSalt hashedPasswordAndSalt = passwordCrypto.hashPassword(password);
        // Generate master AES key
        final AESCrypto.SaltAndKey aesMasterKeyAndSalt = aesCrypto.generateRandomAESKeyFromPasswordGetSalt(password);
        // Generate master MAC key
        final AESCrypto.SaltAndKey macMasterKeyAndSalt = macCrypto.generateRandomMacKeyFromPasswordGetSalt(password);
        // Store the salt values used to generate the aes- and mac-masterkeys
        storeRootSaltData(aesMasterKeyAndSalt.getSalt(), macMasterKeyAndSalt.getSalt());
        // Generate the intermediate aes key and encrypt it with the master key
        AESCrypto.CipherIV intermediateAESCipherIV = aesCrypto.encryptAES(aesCrypto.generateRandomAESKey().getEncoded(),
                aesMasterKeyAndSalt.getSecretKey());
        // Generate the intermediate mac key and encrypt it with the master key
        AESCrypto.CipherIV intermediateMacCipherIv = aesCrypto.encryptAES(macCrypto.generateMacKey().getEncoded(), aesMasterKeyAndSalt.getSecretKey());
        // Generate MAC for encrypted aes-intermediate key and encrypted mac-intermediate key
        byte[] aesIntermediateMac = macCrypto.generateMac(intermediateAESCipherIV.getCipher(), macMasterKeyAndSalt.getSecretKey());
        byte[] macIntermediateMac = macCrypto.generateMac(intermediateMacCipherIv.getCipher(), macMasterKeyAndSalt.getSecretKey());
        // Store MACs for encrypted aes- and mac-intermediate keys
        storeIntermediateKeysMacs(aesIntermediateMac, macIntermediateMac);
        // Store the hashed password+salt, the intermediate key+iv and the mac-key+iv
        storePasswordAndIntermediateKeyCipherIV(hashedPasswordAndSalt, intermediateAESCipherIV, intermediateMacCipherIv);
        // Load the stored keys to check if save was successful
        intermediateAESCipherIV = aesCrypto.getCipherAndIVFromSharedPref(IMEDIATE_KEY_DATA, AES_INTERMEDIATEKEY_ALIAS);
        intermediateMacCipherIv = aesCrypto.getCipherAndIVFromSharedPref(IMEDIATE_KEY_DATA, MAC_INTERMEDIATE_KEY_ALIAS);
        aesIntermediateMac = cryptoIOHelper.loadFromSharedPrefBase64(IMEDIATE_KEY_DATA, AES_INTERMEDIATE_KEY_MAC_ALIAS);
        macIntermediateMac = cryptoIOHelper.loadFromSharedPrefBase64(IMEDIATE_KEY_DATA, MAC_INTERMEDIATE_KEY_MAC_ALIAS);
        // Check the integrity of the newly stored and then loaded intermediate key as failsafe mechanism
        // to check if the key and mac material where generated and stored correctly
        if (macCrypto.checkIntegrity(intermediateAESCipherIV.getCipher(), aesIntermediateMac, macMasterKeyAndSalt.getSecretKey()) &&
                macCrypto.checkIntegrity(intermediateMacCipherIv.getCipher(), macIntermediateMac, macMasterKeyAndSalt.getSecretKey())) {
            // Get the raw key material
            final byte[] rawAES = aesCrypto.decryptAES(intermediateAESCipherIV.getCipher(), intermediateAESCipherIV.getIv(), aesMasterKeyAndSalt.getSecretKey());
            final byte[] rawMAC = aesCrypto.decryptAES(intermediateMacCipherIv.getCipher(), intermediateMacCipherIv.getIv(), aesMasterKeyAndSalt.getSecretKey());
            // Generate the secret-key objects and return them
            return new SecretKeys(new SecretKeySpec(rawAES, 0, rawAES.length, AES), new SecretKeySpec(rawMAC, 0, rawMAC.length, MAC));
        }
        // throw exception if not
        throw new CryptoIOHelper.IntegrityCheckFailedException(INTEGRITY_CHECK_FAILED);
    }

    /**
     * Private method that creates the AES master-key and stores its salt value. Then the intermediate key
     * is generated and stored in the SharedPreferences. The key then is loaded and returned to the caller.
     * @param password      The password from which the master key will be derived.
     * @return              The AES intermediate-key used for data encryption and decryption.
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    private SecretKey createAndStoreAndGetKeyDataWithoutMac(char[] password) throws GeneralSecurityException, CryptoIOHelper.DataNotAvailableException, 
        CryptoIOHelper.IntegrityCheckFailedException {
        // Hash the password with salt and get the hashed password and the salt
        final PasswordCrypto.HashedPasswordAndSalt hashedPasswordAndSalt = passwordCrypto.hashPassword(password);
        // Generate master AES key
        final AESCrypto.SaltAndKey aesMasterKeyAndSalt = aesCrypto.generateRandomAESKeyFromPasswordGetSalt(password);
        // Store the salt values used to generate the aes-key
        storeRootSaltDataWithoutMac(aesMasterKeyAndSalt.getSalt());
        // Generate the intermediate aes key and encrypt it with the master key
        AESCrypto.CipherIV intermediateAESCipherIV = aesCrypto.encryptAES(aesCrypto.generateRandomAESKey().getEncoded(),
                aesMasterKeyAndSalt.getSecretKey());
        // Store the hashed password+salt, the intermediate key+iv and the mac-key+iv
        storePasswordAndIntermediateKeyCipherIVWithoutMac(hashedPasswordAndSalt, intermediateAESCipherIV);
        // Load the stored keys to check if save was successful
        intermediateAESCipherIV = aesCrypto.getCipherAndIVFromSharedPref(IMEDIATE_KEY_DATA, AES_INTERMEDIATEKEY_ALIAS);
        // to check if the key and mac material where generated and stored correctly
        // Get the raw key material
        final byte[] rawAES = aesCrypto.decryptAES(intermediateAESCipherIV.getCipher(), intermediateAESCipherIV.getIv(), aesMasterKeyAndSalt.getSecretKey());
        // Generate the secret-key objects and return them
        return new SecretKeySpec(rawAES, 0, rawAES.length, AES);
    }

    /**
     * Gets the formerly created and stored key data. Returns the AES and MAC intermediate-keys used for encryption, decryption and integrity checking.
     * @param password      The password from the master key will be derived.
     * @return              The AES and MAC intermediate-keys used for data encryption and decryption.
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    private SecretKeys getKeyData(char[] password) throws CryptoIOHelper.NoKeyMaterialException, CryptoIOHelper.IntegrityCheckFailedException, 
        CryptoIOHelper.DataNotAvailableException, GeneralSecurityException, CryptoIOHelper.WrongPasswordException {
        // Get the formerly hashed password and its salt value from Shared Preferences
        try {
            final PasswordCrypto.HashedPasswordAndSalt hashedPasswordAndSalt = passwordCrypto.
                    getHashedPasswordAndSaltSharedPref(PASSWORD_ALIAS, PASSWORD_HASH_ALIAS, PASSWORD_SALT_ALIAS);
            // Check whether the hash of the given password+salt equals the hash of the store password
            if (passwordCrypto.checkPassword(password, hashedPasswordAndSalt.getHashedPassword(), hashedPasswordAndSalt.getSalt())) {
                // Load the salt values for generating the master aes and mac key
                final byte[] aesSalt = cryptoIOHelper.loadFromSharedPrefBase64(KEY_DATA_ALIAS, AES_MASTERKEY_SALT_ALIAS);
                final byte[] macSalt = cryptoIOHelper.loadFromSharedPrefBase64(KEY_DATA_ALIAS, MAC_MASTER_KEY_SALT_ALIAS);
                // Load MACs of aes and mac intermediate keys
                final byte[] intermediateAesKeyMac = cryptoIOHelper.loadFromSharedPrefBase64(IMEDIATE_KEY_DATA, AES_INTERMEDIATE_KEY_MAC_ALIAS);
                final byte[] intermediateMacKeyMac = cryptoIOHelper.loadFromSharedPrefBase64(IMEDIATE_KEY_DATA, MAC_INTERMEDIATE_KEY_MAC_ALIAS);
                // Load the encrypted intermediate key and the encrypted mac key
                final AESCrypto.CipherIV intermediateAESCipherIV = aesCrypto.getCipherAndIVFromSharedPref(IMEDIATE_KEY_DATA, AES_INTERMEDIATEKEY_ALIAS);
                final AESCrypto.CipherIV intermediateMacCipherIv = aesCrypto.getCipherAndIVFromSharedPref(IMEDIATE_KEY_DATA, MAC_INTERMEDIATE_KEY_ALIAS);
                // Generate Master mac-key
                final SecretKey macMasterKey = macCrypto.generateMacKeyFromPasswordSetSalt(password, macSalt);
                // Check if the encrypted intermediate keys are uncorrupted
                if (macCrypto.checkIntegrity(intermediateAESCipherIV.getCipher(), intermediateAesKeyMac, macMasterKey) &&
                        macCrypto.checkIntegrity(intermediateMacCipherIv.getCipher(), intermediateMacKeyMac, macMasterKey)) {
                    // generate Master AES-Key
                    final SecretKey aesMasterKey = aesCrypto.generateAESKeyFromPasswordSetSalt(password, aesSalt);
                    // Extract the raw key data for aes and mac intermediate keys
                    final byte[] aes = aesCrypto.decryptAES(intermediateAESCipherIV.getCipher(), intermediateAESCipherIV.getIv(), aesMasterKey);
                    final byte[] mac = aesCrypto.decryptAES(intermediateMacCipherIv.getCipher(), intermediateMacCipherIv.getIv(), aesMasterKey);
                    // Return the aes and mac intermediate keys
                    return new SecretKeys(new SecretKeySpec(aes, 0, aes.length, AES), new SecretKeySpec(mac, 0, mac.length, MAC));
                } else {
                    // If integrity check failed, throw IntegrityCheckFailedException
                    throw new CryptoIOHelper.IntegrityCheckFailedException(INTEGRITY_CHECK_FAILED);
                }
            } else {
                // If password check failed, throw WrongPasswordException
                throw new CryptoIOHelper.WrongPasswordException(WRONG_PASSWORD);
            }
        } catch (CryptoIOHelper.DataNotAvailableException e) {
            throw new CryptoIOHelper.NoKeyMaterialException(NO_KEYMATERIAL_MSG);
        }
    }

    /**
     * Gets the formerly created and stored key data. Returns the AES intermediate key used for encryption and decryption.
     * @param password      The password from the master key will be derived.
     * @return              The AES intermediate key used for data encryption and decryption.
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws GeneralSecurityException
     * @throws CryptoIOHelper.WrongPasswordException
     * @throws CryptoIOHelper.IntegrityCheckFailedException
     */
    private SecretKey getKeyDataWithoutMac(char[] password) throws CryptoIOHelper.NoKeyMaterialException, CryptoIOHelper.IntegrityCheckFailedException, 
        CryptoIOHelper.DataNotAvailableException, GeneralSecurityException, CryptoIOHelper.WrongPasswordException {
        // Get the formerly hashed password and its salt value from Shared Preferences
        try {
            final PasswordCrypto.HashedPasswordAndSalt hashedPasswordAndSalt = passwordCrypto.
                    getHashedPasswordAndSaltSharedPref(PASSWORD_ALIAS, PASSWORD_HASH_ALIAS, PASSWORD_SALT_ALIAS);

            // Check whether the hash of the given password+salt equals the hash of the store password
            if (passwordCrypto.checkPassword(password, hashedPasswordAndSalt.getHashedPassword(), hashedPasswordAndSalt.getSalt())) {
                // Load the salt value for generating the master aes key
                try {
                    final byte[] aesSalt = cryptoIOHelper.loadFromSharedPrefBase64(KEY_DATA_ALIAS, AES_MASTERKEY_SALT_ALIAS);
                    // Load the encrypted intermediate key
                    final AESCrypto.CipherIV intermediateAESCipherIV = aesCrypto.getCipherAndIVFromSharedPref(IMEDIATE_KEY_DATA, AES_INTERMEDIATEKEY_ALIAS);
                    // generate Master AES-Key
                    final SecretKey aesMasterKey = aesCrypto.generateAESKeyFromPasswordSetSalt(password, aesSalt);
                    // Extract the raw aes key data
                    final byte[] aes = aesCrypto.decryptAES(intermediateAESCipherIV.getCipher(), intermediateAESCipherIV.getIv(), aesMasterKey);
                    // Return the aes intermediate key
                    return new SecretKeySpec(aes, 0, aes.length, AES);
                } catch (CryptoIOHelper.DataNotAvailableException e) {
                    throw new CryptoIOHelper.NoKeyMaterialException(NO_KEYMATERIAL_MSG);
                }
            } else {
                // If password check failed, throw WrongPasswordException
                throw new CryptoIOHelper.WrongPasswordException(WRONG_PASSWORD);
            }
        } catch (CryptoIOHelper.DataNotAvailableException e) {
            throw new CryptoIOHelper.NoKeyMaterialException(NO_KEYMATERIAL_MSG);
        }
    }

    /**
     * Method that stores the provided Objects in the SharedPreferences.
     * @param hashedPasswordAndSalt     The hashed password and corresponding salt value.
     * @param intermediateAESCipherIV   The encrypted intermediate aes key and the corresponding iv.
     * @param intermediateMacCipherIV   The encrypted intermediate mac key and the corresponding iv.
     */
    private void storePasswordAndIntermediateKeyCipherIV(PasswordCrypto.HashedPasswordAndSalt hashedPasswordAndSalt, AESCrypto.CipherIV intermediateAESCipherIV,
                                                         AESCrypto.CipherIV intermediateMacCipherIV) {
        // Store the hashed password+salt, the intermediate key+iv and the mac-key+iv
        passwordCrypto.storeHashedPasswordAndSaltSharedPref(hashedPasswordAndSalt, PASSWORD_ALIAS, PASSWORD_HASH_ALIAS, PASSWORD_SALT_ALIAS);
        aesCrypto.saveCipherAndIVToSharedPrefBase64(intermediateAESCipherIV, IMEDIATE_KEY_DATA, AES_INTERMEDIATEKEY_ALIAS);
        aesCrypto.saveCipherAndIVToSharedPrefBase64(intermediateMacCipherIV, IMEDIATE_KEY_DATA, MAC_INTERMEDIATE_KEY_ALIAS);
    }

    /**
     * Method that stores the provided Objects in the SharedPreferences.
     * @param hashedPasswordAndSalt     The hashed password and corresponding salt value.
     * @param intermediateAESCipherIV   The encrypted intermediate aes key and the corresponding iv.
     */
    private void storePasswordAndIntermediateKeyCipherIVWithoutMac(PasswordCrypto.HashedPasswordAndSalt hashedPasswordAndSalt, AESCrypto.CipherIV intermediateAESCipherIV) {
        // Store the hashed password+salt and the intermediate key+iv
        passwordCrypto.storeHashedPasswordAndSaltSharedPref(hashedPasswordAndSalt, PASSWORD_ALIAS, PASSWORD_HASH_ALIAS, PASSWORD_SALT_ALIAS);
        aesCrypto.saveCipherAndIVToSharedPrefBase64(intermediateAESCipherIV, IMEDIATE_KEY_DATA, AES_INTERMEDIATEKEY_ALIAS);
    }

    /**
     * Method that stores the salt values of the root aes- and mac-keys.
     * @param saltAESKey    The salt value used to generate the master aes-key.
     * @param saltMACKey    The salt value used to generate the master mac-key.
     */
    private void storeRootSaltData(byte[] saltAESKey, byte[] saltMACKey) {
        // Save the salt used to generate the aes master-key in Shared Preferences
        cryptoIOHelper.saveToSharedPrefBase64(KEY_DATA_ALIAS, AES_MASTERKEY_SALT_ALIAS, saltAESKey);
        // Save the salt used to generate the mac master-key in Shared Preferences
        cryptoIOHelper.saveToSharedPrefBase64(KEY_DATA_ALIAS, MAC_MASTER_KEY_SALT_ALIAS, saltMACKey);
    }

    /**
     * Method that stores the salt value of the root aes-key.
     * @param saltAESKey    The salt value used to generate the master aes-key.
     */
    private void storeRootSaltDataWithoutMac(byte[] saltAESKey) {
        // Save the salt used to generate the aes master-key in Shared Preferences
        cryptoIOHelper.saveToSharedPrefBase64(KEY_DATA_ALIAS, AES_MASTERKEY_SALT_ALIAS, saltAESKey);
    }

    /**
     * Method that stores the macs of the intermediate aes- and mac-key-
     * @param aesIntermediateMac    The mac of the intermediate aes key.
     * @param macIntermediateMac    The mac of the intermediate mac key.
     */
    private void storeIntermediateKeysMacs(byte[] aesIntermediateMac, byte[] macIntermediateMac) {
        // Store MACs for encrypted aes- and mac-intermediate keys
        cryptoIOHelper.saveToSharedPrefBase64(IMEDIATE_KEY_DATA, AES_INTERMEDIATE_KEY_MAC_ALIAS, aesIntermediateMac);
        cryptoIOHelper.saveToSharedPrefBase64(IMEDIATE_KEY_DATA, MAC_INTERMEDIATE_KEY_MAC_ALIAS, macIntermediateMac);
    }

     /**
     * Private method that saves the provided array consisting of iv, cipher and mac.
     * @param mode         The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
     * @param ivAndCipherAndMac     The byte array containing the ciphertext and iv and mac.
     * @param alias        The storage alias.
     * @throws IOException
     * @throws CryptoIOHelper.WrongModeException
     */
    private void saveUserCipherMacIv(int mode, byte[] ivAndCipherAndMac, String alias) throws IOException, CryptoIOHelper.WrongModeException {
        final byte[] temp = cryptoIOHelper.decodeBase64(ivAndCipherAndMac);
        final byte[] iv = new byte[IV_LENGTH_BYTE];
        final byte[] mac = new byte[MAC_LENGTH_BYTE];
        final byte[] cipher = new byte[temp.length - (IV_LENGTH_BYTE + MAC_LENGTH_BYTE)];
        disassembleIvAndCipherAndMac(iv, mac, cipher, temp);
        if (mode == SHARED_PREFERENCES) {
            aesCrypto.saveCipherAndIVToSharedPrefBase64(aesCrypto.instantiateCipherIV(cipher, iv), CIPHER_IV_ALIAS, alias);
            //aesCrypto.saveToSharedPrefBase64(MAC_USER_ALIAS, alias, mac);
            macCrypto.saveToSharedPrefBase64(MAC_USER_ALIAS, alias, mac);
            // For testing encryption
            //aesCrypto.saveToSharedPrefBase64(CIPHER_IV_ALIAS, alias + "klartext", "Mein Testtext zum Prüfen".getBytes("UTF-8"));
        } else if (mode == FILE) {
            aesCrypto.writeCipherAndIVToFileBase64(aesCrypto.instantiateCipherIV(cipher, iv), alias);
            //aesCrypto.saveBytesToFileBase64(alias, mac);
            macCrypto.saveBytesToFileBase64(alias, mac);
            // For testing encryption
            //aesCrypto.saveBytesToFileBase64(alias+"klartext", "Mein Testtext zum Prüfen".getBytes("UTF-8"));
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_MODE_EXCEPTION);
        }
    }

    /**
     * Private method that saves the provided array consisting of iv and cipher.
     * @param mode         The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
     * @param ivAndCipher  The byte array containing the ciphertext and iv.
     * @param alias        The storage alias.
     * @throws IOException
     * @throws CryptoIOHelper.WrongModeException
     */
    private void saveUserCipherIv(int mode, byte[] ivAndCipher, String alias) throws IOException, CryptoIOHelper.WrongModeException {
        final byte[] temp = cryptoIOHelper.decodeBase64(ivAndCipher);
        final byte[] iv = new byte[IV_LENGTH_BYTE];
        final byte[] cipher = new byte[temp.length - IV_LENGTH_BYTE];
        disassembleIvAndCipher(iv, cipher, temp);
        if (mode == SHARED_PREFERENCES) {
            aesCrypto.saveCipherAndIVToSharedPrefBase64(aesCrypto.instantiateCipherIV(cipher, iv), CIPHER_IV_ALIAS, alias);
        } else if (mode == FILE) {
            aesCrypto.writeCipherAndIVToFileBase64(aesCrypto.instantiateCipherIV(cipher, iv), alias);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_MODE_EXCEPTION);
        }
    }

//    /**
//     * Private method that saves the provided array consisting of iv and cipher.
//     * @param mode         The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
//     * @param ivAndCipherAndMac     The byte array containing the ciphertext and iv and mac.
//     * @param alias        The storage alias.
//     * @throws IOException
//     * @throws CryptoIOHelper.WrongModeException
//     */
//    private void saveUserCipherMacIv(int mode, byte[] ivAndCipherAndMac, String alias) throws IOException, CryptoIOHelper.WrongModeException {
//        final byte[] temp = cryptoIOHelper.decodeBase64(ivAndCipherAndMac);
//        final byte[] iv = new byte[IV_LENGTH_BYTE];
//        final byte[] mac = new byte[MAC_LENGTH_BYTE];
//        final byte[] cipher = new byte[temp.length - (IV_LENGTH_BYTE + MAC_LENGTH_BYTE)];
//        disassembleIvAndCipherAndMac(iv, mac, cipher, temp);
//        if (mode == SHARED_PREFERENCES) {
//            aesCrypto.saveCipherAndIVToSharedPrefBase64(aesCrypto.instantiateCipherIV(cipher, iv), CIPHER_IV_ALIAS, alias);
//            //aesCrypto.saveToSharedPrefBase64(MAC_USER_ALIAS, alias, mac);
//            macCrypto.saveToSharedPrefBase64(MAC_USER_ALIAS, alias, mac);
//            // For testing encryption
//            //aesCrypto.saveToSharedPrefBase64(CIPHER_IV_ALIAS, alias + "klartext", "Mein Testtext zum Prüfen".getBytes("UTF-8"));
//        } else if (mode == FILE) {
//            aesCrypto.writeCipherAndIVToFileBase64(aesCrypto.instantiateCipherIV(cipher, iv), alias);
//            //aesCrypto.saveBytesToFileBase64(alias, mac);
//            macCrypto.saveBytesToFileBase64(alias, mac);
//            // For testing encryption
//            //aesCrypto.saveBytesToFileBase64(alias+"klartext", "Mein Testtext zum Prüfen".getBytes("UTF-8"));
//        } else {
//            throw new CryptoIOHelper.WrongModeException(WRONG_MODE_EXCEPTION);
//        }
//    }

    /**
     * Private method that returns a formerly stored CipherIV object.
     * @param mode      The storage mode. SecureAndroid.SHARED_PREFERENCES and SecureAndroid.FILE are possible.
     * @param alias     The storage alias.
     * @return          The CipherIV object.
     * @throws CryptoIOHelper.WrongModeException
     * @throws CryptoIOHelper.DataNotAvailableException
     * @throws IOException
     */
    private AESCrypto.CipherIV getUserCipherIv (int mode, String alias) throws CryptoIOHelper.WrongModeException, CryptoIOHelper.DataNotAvailableException, IOException {
        if (mode == SHARED_PREFERENCES) {
            return aesCrypto.getCipherAndIVFromSharedPref(CIPHER_IV_ALIAS, alias);
        } else if (mode == FILE) {
            return aesCrypto.getCipherAndIVFromFile(alias);
        } else {
            throw new CryptoIOHelper.WrongModeException(WRONG_MODE_EXCEPTION);
        }
    }

    /**
     * Checks whether a suitable algorithm for PBKD is available.
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    private void checkMacLength() throws CryptoIOHelper.NoAlgorithmAvailableException {
        final LinkedList<String> algorithms = cryptoIOHelper.providerCheck();
        if (algorithms.contains("HmacSHA256")) {
            MAC_LENGTH_BYTE = 32;
        } else if (algorithms.contains("HMACSHA256")) {
            MAC_LENGTH_BYTE = 32;
        } else if (algorithms.contains("HmacSHA1")) {
            MAC_LENGTH_BYTE = 20;
        } else if (algorithms.contains("HMACSHA1")) {
            MAC_LENGTH_BYTE = 20;
        } else {
            throw new CryptoIOHelper.NoAlgorithmAvailableException(NO_ALG_MSG);
        }
    }

    // Class to hold a mac and aes key.
    private class SecretKeys {
        private SecretKey mac, aes;
        /**
         * Constructor for SecretKeys
         * @param mac   The mac key.
         * @param aes   The aes key.
         */
        public SecretKeys(SecretKey mac, SecretKey aes) {
            this.mac = mac;
            this.aes = aes;
        }
        // Getter and setter
        public SecretKey getMacKey() { return mac; }
        //public void setMacKey(SecretKey mac) { this.mac = mac; }
        public SecretKey getAesKey() { return aes; }
        //public void setAesKey(SecretKey aes) { this.aes = aes; }
    }
}
