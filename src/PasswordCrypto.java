package my.secureandroid;

import android.content.Context;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Class that implements cryptographic password-operations.
 */

public class PasswordCrypto extends CryptoIOHelper {

    // Messages
    private static final String NO_ALG_MSG = "No algorithm available on this platform";
    private static final String NO_KEY_MAT_MSG = "Propably no key material saved formerly";
    // For storage
    private String SALT_PART = "salt";
    private String HASH_PART = "hash";
    // PBE-Mode
    private String PBE_ALGORITHM;
    // Key length, iterations, salt length
    private static int PBE_ITERATIONS;// = 5000;
    private static final int PBE_SALT_LENGTH_BYTE = 64;
    private static int KEY_LENGTH;
    // For PRNGX-Fix
    private static AtomicBoolean prng;

    /**
     * Constructor for PasswordCrypto Class. Sets the context of the superclass.
     *
     * @param context    The context.
     * @param iterations The iteration count for hashing/PBKDF.
     * @throws NoAlgorithmAvailableException
     */
    protected PasswordCrypto(Context context, int iterations) throws NoAlgorithmAvailableException {
        // Call the superclass
        super(context);
        // Check provider availability
        providerCheckPasswordCrypto();
        // Apply Googles pseudo random number generator fix for API-Level 16-18
        prng = new AtomicBoolean(false);
        fixPrng();
        // set the iteration count
        PBE_ITERATIONS = iterations;
    }

    /**
     * Hashes a password with the PBKDF2WithHmacSHA512 or the PBKDF2WithHmacSHA1 algorithm
     * (depending on the availability on the present platform).
     *
     * @param password The password.
     * @return The hashed password and the salt the password was hashed with.
     * @throws GeneralSecurityException
     */
    protected HashedPasswordAndSalt hashPassword(char[] password) throws GeneralSecurityException {
        fixPrng();
        // Generate the salt
        final byte[] salt = super.generateRandomBytes(PBE_SALT_LENGTH_BYTE);
        // Instantiate key specifications with desired parameters
        final KeySpec keySpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, KEY_LENGTH);
        // Instantiate key factory with the desired PBE-Algorithm
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        // Generate hash und return the hash with the salt that was uses to generate the hash
        return new HashedPasswordAndSalt(keyFactory.generateSecret(keySpec).getEncoded(), salt);
    }

    /**
     * Hashes a password with the PBKDF2WithHmacSHA512 or the PBKDF2WithHmacSHA1 algorithm (depending on the availability
     * on the present platform) with the given salt.
     *
     * @param password The password.
     * @param salt     The salt.
     * @return The hashed password.
     * @throws GeneralSecurityException
     */
    protected byte[] hashPasswordWithSalt(char[] password, byte[] salt) throws GeneralSecurityException {
        // Instantiate key specifications with desired parameters
        final KeySpec keySpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, KEY_LENGTH);
        // Instantiate key factory with the desired PBE-Algorithm
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        // Return the hashed password
        return keyFactory.generateSecret(keySpec).getEncoded();
    }

    /**
     * Checks the given password and salt against the given hash value.
     *
     * @param password The password as a String.
     * @param hash     The hash as a byte array.
     * @param salt     The salt that the hash was generated with.
     * @return true if check was successful, false otherwise
     * @throws GeneralSecurityException
     */
    protected boolean checkPassword(char[] password, byte[] hash, byte[] salt) throws GeneralSecurityException {
        return MessageDigest.isEqual(hashPasswordWithSalt(password, salt), hash);
    }

    /**
     * Stores hashed password in specified file. The file is accessible only by your app.
     *
     * @param filename The filename.
     * @param hash     The hashed password.
     * @throws IOException
     */
    protected void storeHashInFileBase64(String filename, byte[] hash) throws IOException {
        super.saveBytesToFileBase64(filename, hash);
    }

    /**
     * Retrieves hashed password as byte array from specified file.
     *
     * @param filename The filename.
     * @return The hash.
     * @throws IOException
     */
    protected byte[] getHashFromFile(String filename) throws IOException {
        return super.readBytesFromFile(filename);
    }

    /**
     * Retrieves salt as byte array from specified file.
     *
     * @param filename The filename.
     * @return The salt.
     * @throws IOException
     */
    protected byte[] getSaltFromFile(String filename) throws IOException {
        return super.readBytesFromFile(filename);
    }

    /**
     * Stores hashed password in specified file. The file is accessible only by your app.
     *
     * @param spAlias   The alias for the SharedPref.
     * @param hashAlias The alias under which the hash is stored in SharePref.
     * @param hash      The hashed password.
     */
    protected void storeHashInSharedPrefBase64(String spAlias, String hashAlias, byte[] hash) {
        super.saveToSharedPrefBase64(spAlias, hashAlias, hash);
    }

    /**
     * Retrieves hashed password as byte array from specified shared preference
     *
     * @param spAlias   The alias for the SharedPref.
     * @param hashAlias The alias under which the hash is stored in SharePref.
     * @return The hash.
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    protected byte[] getHashFromSharedPref(String spAlias, String hashAlias) throws DataNotAvailableException {
        return super.loadFromSharedPrefBase64(spAlias, hashAlias);
    }

    /**
     * Store the salt value under the specified filename.
     *
     * @param filename The filename.
     * @param salt     The salt to be stored.
     * @throws IOException
     */
    protected void storeSaltInFileBase64(String filename, byte[] salt) throws IOException {
        super.saveBytesToFileBase64(filename, salt);
    }

    /**
     * Stores hashed password in specified file. The file is accessible only by your app.
     *
     * @param spAlias   The alias for the SharedPref.
     * @param saltAlias The alias under which the salt is stored in SharePref.
     * @param salt      The salt.
     */
    protected void storeSaltInSharedPrefBase64(String spAlias, String saltAlias, byte[] salt) {
        super.saveToSharedPrefBase64(spAlias, saltAlias, salt);
    }

    /**
     * Retrieves the salt.
     *
     * @param spAlias   The alias for the SharedPref.
     * @param saltAlias The alias for the salt within the SharedPref.
     * @return The salt as a byte array.
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    protected byte[] getSaltFromSharedPref(String spAlias, String saltAlias) throws DataNotAvailableException {
        return super.loadFromSharedPrefBase64(spAlias, saltAlias);
    }

    /**
     * Stores the hashed password and the salt in the HashedPasswordAndSalt object to the specified
     * SharedPreferences file under the given aliases.
     *
     * @param hashedPasswordAndSalt The object containing the password hash and the salt.
     * @param spAlias               The alias for the SharedPreferences.
     * @param passwordAlias         The alias for the hashed password within the SharedPreferences.
     * @param saltAlias             The alias for the salt within the SharedPreferences.
     */
    protected void storeHashedPasswordAndSaltSharedPref(HashedPasswordAndSalt hashedPasswordAndSalt, String spAlias, String passwordAlias, String saltAlias) {
        storeHashInSharedPrefBase64(spAlias, passwordAlias, hashedPasswordAndSalt.getHashedPassword());
        storeSaltInSharedPrefBase64(spAlias, saltAlias, hashedPasswordAndSalt.getSalt());
    }

    /**
     * Returns the HashedPasswordAndSalt object saved under the specified aliases in the SharedPreferences.
     *
     * @param spAlias       The alias for the SharedPreferences.
     * @param passwordAlias The alias for the hashed password.
     * @param saltAlias     The alias for the salt.
     * @return The HashedPasswordAndSalt object.
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    protected HashedPasswordAndSalt getHashedPasswordAndSaltSharedPref(String spAlias, String passwordAlias, String saltAlias) throws DataNotAvailableException {
        return new HashedPasswordAndSalt(getHashFromSharedPref(spAlias, passwordAlias), getSaltFromSharedPref(spAlias, saltAlias));
    }

    // Class to hold a HASHED! password and the corresponding salt as byte arrays.
    protected class HashedPasswordAndSalt {

        private byte[] password, salt;

        protected HashedPasswordAndSalt(byte[] password, byte[] salt) {
            this.password = password;
            this.salt = salt;
        }

        protected byte[] getHashedPassword() {
            return password;
        }
        protected byte[] getSalt() {
            return salt;
        }
    }

    /**
     * Checks whether a suitable algorithm for PBKD is available.
     *
     * @throws NoAlgorithmAvailableException
     */
    private void providerCheckPasswordCrypto() throws NoAlgorithmAvailableException {
        final LinkedList<String> algorithms = super.providerCheck();
        if (algorithms.contains("PBKDF2WithHmacSHA256")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA256";
            KEY_LENGTH = 256;
        } else if (algorithms.contains("PBKDF2WithHmacSHA1")) {
            PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
            KEY_LENGTH = 160;
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

    // Not yet needed
    /**
     * Returns a HashedPasswordAndSalt instance.
     *
     * @param password The password.
     * @param salt     The salt.
     * @return The HashedPasswordAndSalt object.
     */
    protected HashedPasswordAndSalt instantiateHashedPasswordAndSalt(byte[] password, byte[] salt) {
        return new HashedPasswordAndSalt(password, salt);
    }

    /**
     * Stores the HashedPasswordAndSalt object in the specified file.
     *
     * @param hashedPasswordAndSalt The HashedPasswordAndSalt object.
     * @param filename              The filename.
     * @throws IOException
     */
    protected void storeHashedPasswordAndSaltFile(HashedPasswordAndSalt hashedPasswordAndSalt, String filename) throws IOException {
        storeHashInFileBase64(filename + HASH_PART, hashedPasswordAndSalt.getHashedPassword());
        storeSaltInFileBase64(filename + SALT_PART, hashedPasswordAndSalt.getSalt());
    }

    /**
     * Retrieves the specified object from the filesystem.
     *
     * @param filename The filename.
     * @return The HashedPasswordAndSalt object.
     * @throws IOException
     */
    protected HashedPasswordAndSalt getHashedPasswordAndSaltFromFile(String filename) throws IOException {
        return new HashedPasswordAndSalt(getHashFromFile(filename + HASH_PART), getSaltFromFile(filename + SALT_PART));
    }
}