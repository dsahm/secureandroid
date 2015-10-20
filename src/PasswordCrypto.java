package my.secureandroid;

import android.content.Context;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.LinkedList;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordCrypto extends CryptoIOHelper {

    // Message if no suitable algorithm available
    private static final String NO_ALG_MSG = "No algorithm available on this platform";
    // For storage
    private String SALT_PART = "salt";
    private String HASH_PART = "hash";
    // PBE-Mode
    private String PBE_ALGORITHM;
    // Key length, iterations, salt length
    private static int PBE_ITERATIONS;// = 5000;
    private static final int PBE_SALT_LENGTH_BYTE = 64;
    private static int KEY_LENGTH;

    /**
     * Constructor for PasswordCrypto Class. Sets the context of the superclass.
     * @param context   The context.
     * @param iterations The iteration count for hashing.
     * @throws NoAlgorithmAvailableException
     */
    public PasswordCrypto(Context context, int iterations) throws NoAlgorithmAvailableException {
        // Call the superclass
        super(context);
        // Check provider availability
        providerCheckPasswordCrypto();
        // Apply Googles pseudo random number generator fix for API-Level 16-18
        fixPrng();
        // set the iteration count
        PBE_ITERATIONS = iterations;
    }

    /**
     * Hashes a password with the PBKDF2WithHmacSHA512 or the PBKDF2WithHmacSHA1 algorithm
     * (depending on the availability on the present platform)
     * @param password      the password
     * @return              the hashed password and the salt the was password was hashed with
     * @throws GeneralSecurityException
     */
    public HashedPasswordAndSalt hashPassword (char[] password) throws GeneralSecurityException {
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
     * @param password  The password.
     * @param salt      The salt.
     * @return          The hashed password.
     * @throws GeneralSecurityException
     */
    public byte [] hashPasswordWithSalt (char[] password, byte [] salt) throws GeneralSecurityException {
        // Instantiate key specifications with desired parameters
        final KeySpec keySpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, KEY_LENGTH);
        // Instantiate key factory with the desired PBE-Algorithm
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        // Return the hashed password
        return keyFactory.generateSecret(keySpec).getEncoded();
    }

    /**
     * Checks the given password against the given hash value
     * @param password  the password as a String
     * @param hash      the hash as a byte array
     * @return          true if check was successful, false otherwise
     * @throws GeneralSecurityException
     */
    public boolean checkPassword(char[] password, byte[] hash, byte[] salt) throws GeneralSecurityException {
        return Arrays.equals(hashPasswordWithSalt(password, salt), hash);
    }

    /**
     * Stores hashed password in specified file. The file is accessible only by your app.
     * @param filename      the filename
     * @param hash          the hashed password
     * @throws IOException
     */
    public void storeHashInFileBase64(String filename, byte[] hash) throws IOException {
        super.saveBytesToFileBase64(filename, hash);
    }

    /**
     * Retrieves hashed password as byte array from specified file.
     * @param filename      the filename
     * @return              the hash
     * @throws IOException
     */
    public byte[] getHashFromFile(String filename) throws IOException {
        return super.readBytesFromFile(filename);
    }

    /**
     * Retrieves salt as byte array from specified file.
     * @param filename      the filename
     * @return              the salt
     * @throws IOException
     */
    public byte[] getSaltFromFile(String filename) throws IOException {
        return super.readBytesFromFile(filename);
    }

    /**
     * Stores hashed password in specified file. The file is accessible only by your app.
     * @param spAlias         the alias for the SharedPref
     * @param hashAlias       the alias under which the hash is stored in SharePref
     * @param hash            the hashed password
     */
    public void storeHashInSharedPrefBase64(String spAlias, String hashAlias, byte[] hash) {
        super.saveToSharedPrefBase64(spAlias, hashAlias, hash);
    }

    /**
     * Retrieves hashed password as byte array from specified shared preference.
     * @param spAlias       the alias for the SharedPref
     * @param hashAlias     the alias under which the hash is stored in SharePref
     * @return              the hash
     * @throws              CryptoIOHelper.DataNotAvailableException
     */
    public byte[] getHashFromSharedPref(String spAlias, String hashAlias) throws DataNotAvailableException {
        return super.loadFromSharedPrefBase64(spAlias, hashAlias);
    }

    /**
     * Store the salt value under the specified filename.
     * @param filename  The filename.
     * @param salt      The salt to be stored.
     * @throws IOException
     */
    public void storeSaltInFileBase64(String filename, byte[] salt) throws IOException {
        super.saveBytesToFileBase64(filename, salt);
    }

    /**
     * Stores hashed password in specified file. The file is accessible only by your app.
     * @param spAlias         the alias for the SharedPref
     * @param saltAlias       the alias under which the salt is stored in SharePref
     * @param salt            the salt
     */
    public void storeSaltInSharedPrefBase64(String spAlias, String saltAlias, byte[] salt) {
        super.saveToSharedPrefBase64(spAlias, saltAlias, salt);
    }

    /**
     * Retrieves the salt.
     * @param spAlias       The alias for the SharedPref.
     * @param saltAlias     The alias for the salt within the SharedPref.
     * @return              The salt as a byte array.
     * @throws              CryptoIOHelper.DataNotAvailableException
     */
    public byte[] getSaltFromSharedPref(String spAlias, String saltAlias) throws DataNotAvailableException {
        return super.loadFromSharedPrefBase64(spAlias, saltAlias);
    }

    /**
     * Stores the hashed password and the salt in the HashedPasswordAndSalt object to the specified
     * SharedPreferences file under the given aliases.
     * @param hashedPasswordAndSalt       The object containing the password hash and the salt.
     * @param spAlias               The alias for the SharedPreferences.
     * @param passwordAlias         The alias for the hashed password within the SharedPreferences.
     * @param saltAlias             The alias for the salt within the SharedPreferences.
     */
    public void storeHashedPasswordAndSaltSharedPref(HashedPasswordAndSalt hashedPasswordAndSalt, String spAlias, String passwordAlias, String saltAlias) {
        storeHashInSharedPrefBase64(spAlias, passwordAlias, hashedPasswordAndSalt.getHashedPassword());
        storeSaltInSharedPrefBase64(spAlias, saltAlias, hashedPasswordAndSalt.getSalt());
    }

    /**
     * Returns the HashedPasswordAndSalt object saved under the specified aliases in the SharedPreferences.
     * @param spAlias           The alias for the SharePreferences.
     * @param passwordAlias     The alias for the hashed password.
     * @param saltAlias         The alias for the salt.
     * @return                  The HashedPasswordAndSalt object.
     * @throws                  CryptoIOHelper.DataNotAvailableException
     */
    public HashedPasswordAndSalt getHashedPasswordAndSaltSharedPref(String spAlias, String passwordAlias, String saltAlias) throws DataNotAvailableException {
        return new HashedPasswordAndSalt(getHashFromSharedPref(spAlias, passwordAlias), getSaltFromSharedPref(spAlias, saltAlias));
    }

    /**
     * Stores the HashedPasswordAndSalt object in the specified file.
     * @param hashedPasswordAndSalt      The HashedPasswordAndSalt object.
     * @param filename                   The filename.
     * @throws IOException
     */
    public void storeHashedPasswordAndSaltFile(HashedPasswordAndSalt hashedPasswordAndSalt, String filename) throws IOException {
        storeHashInFileBase64(filename+HASH_PART, hashedPasswordAndSalt.getHashedPassword());
        storeSaltInFileBase64(filename+SALT_PART, hashedPasswordAndSalt.getSalt());
    }

    /**
     * Retrieves the specified object from the filesystem.
     * @param filename      The filename.
     * @return              The HashedPasswordAndSalt object.
     * @throws IOException
     */
    public HashedPasswordAndSalt getHashedPasswordAndSaltFromFile(String filename) throws IOException {
        return new HashedPasswordAndSalt(getHashFromFile(filename + HASH_PART), getSaltFromFile(filename+SALT_PART));
    }

    /**
     * Checks whether a suitable algorithm for PBKD is available.
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
     * Will only run once, and every subsequent call should return immediately.
     */
    private static void fixPrng() {
        synchronized (PRNGFixes.class) {
            PRNGFixes.apply();
        }
    }

    // Class to hold a HASHED! password and the corresponding salt as byte arrays
    public class HashedPasswordAndSalt {

        private byte[] password, salt;

        public HashedPasswordAndSalt(byte[] password, byte[] salt) {
            this.password = password;
            this.salt = salt;
        }

        public byte[] getHashedPassword() {
            return password;
        }
        public byte[] getSalt() {
            return salt;
        }
    }

    /**
     * Returns a HashedPasswordAndSalt instance
     * @param password  The password.
     * @param salt      The salt.
     * @return          The HashedPasswordAndSalt object.
     */
    public HashedPasswordAndSalt instantiateHashedPasswordAndSalt(byte[] password, byte[] salt) {
        return new HashedPasswordAndSalt(password, salt);
    }


    // Bisher nicht benötigt
    /**
     * Retrieves the salt value stored under the specified filename.
     * @param filename  The filename.
     * @return          The salt value as byte array.
     * @throws IOException
     */
    public byte[] getSaltFromFileBase64(String filename) throws IOException {
        return super.readBytesFromFile(filename);
    }
}
