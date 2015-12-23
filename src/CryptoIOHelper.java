package my.secureandroid;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.LinkedList;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Helper class.
 */

public class CryptoIOHelper {

    // Context
    private Context context;
    // Exception messages
    private final static String DATA_NOT_AVAILABLE = "Data not available";
    // Message if no suitable algorithm available
    private static final String NO_ALG_MSG = "No algorithm available on this platform";
    // Variables for performance test
    private static String PBE_ALGORITHM;
    private static final int PBE_SALT_LENGTH_BYTE = 64;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_BASE = 1000;
    // For PRNG-Fix
    private static AtomicBoolean prng;

    /**
     * Constructor, sets the context.
     *
     * @param context The context.
     */
    protected CryptoIOHelper (Context context) {
        this.context = context;
        // Apply Googles pseudo random number generator fix
        prng = new AtomicBoolean(false);
        fixPrng();
    }

    /**
     * Encodes the given byte array to a Base64 byte array.
     *
     * @param data  The byte array to be encoded.
     * @return      The encoded byte array.
     */
    protected byte[] encodeToBase64(byte[] data) {
        return Base64.encode(data, Base64.NO_WRAP);
    }

    /**
     * Encodes the given byte array to a Base64-String.
     *
     * @param data  The byte array to be encoded.
     * @return      The encoded String.
     */
    protected String encodeToBase64String(byte[] data) {
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    /**
     * Decodes the given Base64-encoded byte array.
     *
     * @param data      The Base64-encoded byte array.
     * @return          The decoded data as byte array.
     */
    // public for testing purposes
    protected byte[] decodeBase64(byte[] data) {
        return Base64.decode(data, Base64.NO_WRAP);
    }

    /**
     * Decodes the given Base64-encoded String.
     *
     * @param data      The Base64-encoded String.
     * @return          The decoded data as byte array.
     */
    protected byte[] decodeBase64String(String data) {
        return Base64.decode(data, Base64.NO_WRAP);
    }

    /**
     * Deletes the specified file.
     *
     * @param filename  The filename to be deleted.
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    protected void deleteFile  (String filename) throws DataNotAvailableException {
        final String dir = context.getFilesDir().getAbsolutePath();
        final File file = new File(dir, filename);
        final boolean deleted = file.delete();
        if (!deleted) {
            throw new DataNotAvailableException(DATA_NOT_AVAILABLE);
        }
    }

    /**
     * Deletes the specified SharedPref file.
     *
     * @param alias     The alias for the SharedPref to be deleted.
     */
    protected void deleteSharedPref(String alias) {
        final SharedPreferences sharedPreferences = context.getSharedPreferences(alias, Context.MODE_PRIVATE);
        final SharedPreferences.Editor spEditor = sharedPreferences.edit();
        spEditor.clear();
        spEditor.apply();
    }

    /**
     * Deletes the alias from specified SharedPref file.
     *
     * @param spAlias   The SharedPreferences alias.
     * @param alias     The alias for the file to be deleted.
     */
    protected void deleteFromSharedPref(String spAlias, String alias) {
        final SharedPreferences sharedPreferences = context.getSharedPreferences(spAlias, Context.MODE_PRIVATE);
        final SharedPreferences.Editor spEditor = sharedPreferences.edit();
        spEditor.remove(alias);
        spEditor.apply();
    }

    /**
     * Saves byte array to the specified file in the app folder, encodes the bytes to Base64
     * before writing. The file will only be accessible to your app.
     *
     * @param filename      The filename under which the data should be stored.
     * @param write         The data to be stored.
     * @throws IOException
     */
    protected void saveBytesToFileBase64(String filename, byte[] write) throws IOException {
        final FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE);
        fos.write(this.encodeToBase64(write));
        fos.close();
    }

    /**
     * Reads a formerly saved byte array from the given file in the app folder,
     * must have been Base64-encoded.
     *
     * @param filename      The filename.
     * @return              The data as byte array.
     * @throws IOException
     */
    protected byte[] readBytesFromFile(String filename) throws IOException {
        final FileInputStream fis = context.openFileInput(filename);
        final byte [] buffer = new byte[(int) fis.getChannel().size()];
        fis.read(buffer);
        fis.close();
        return this.decodeBase64(buffer);
    }

    /**
     * Saves data as Base64-encoded String in the app's SharedPreferences. Will only
     * be accessible by your app.
     *
     * @param spAlias     The alias under which the SharedPref is to be stored.
     * @param dataAlias   The alias of the data itself.
     * @param data        The data as byte array.
     */
    protected void saveToSharedPrefBase64(String spAlias, String dataAlias, byte[] data) {
        final SharedPreferences sharedPreferences = context.getSharedPreferences(spAlias, Context.MODE_PRIVATE);
        final SharedPreferences.Editor spEditor = sharedPreferences.edit();
        spEditor.putString(dataAlias, this.encodeToBase64String(data));
        spEditor.apply();
    }

    /**
     * Reads the data saved under the specified alias. Data must have been saved
     * Base64-encoded.
     *
     * @param spAlias       The alias under which the SharePref was stored.
     * @param dataAlias     The alias of the data itself.
     * @return              The data as byte array.
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    protected byte[] loadFromSharedPrefBase64(String spAlias, String dataAlias) throws DataNotAvailableException {
            final SharedPreferences sharedPreferences = context.getSharedPreferences(spAlias, Context.MODE_PRIVATE);
            String temp = sharedPreferences.getString(dataAlias, null);
            if (temp != null) {
                return decodeBase64String(temp);
            } else {
                throw new DataNotAvailableException(DATA_NOT_AVAILABLE);
            }
    }

    /**
     * Method for Debugging Purposes. Checks which Cryptographic Providers are available
     * on the present platform. Returns a LinkedList with the algorithms that are available
     * on the present Platform.
     */
    protected LinkedList<String> providerCheck() {
        // List all providers
        LinkedList<String> algorithmList = new LinkedList<String>();
        final Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            final Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                Log.i("CRYPTO", "  algorithm: " + service.getAlgorithm());
                algorithmList.add(service.getAlgorithm());
            }
        }
        return algorithmList;
    }

    /**
     * Generates a random byte array that can be used as a salt or for any
     * other similar purpose.
     *
     * @param length    The desired length of the salt (array) in byte.
     * @return          The byte array, length bytes long.
     */
    protected byte[] generateRandomBytes(int length) {
        fixPrng();
        SecureRandom secureRandom = new SecureRandom();
        byte[] random = new byte[length];
        secureRandom.nextBytes(random);
        return random;
    }

    /**
     * Return pseudo unique ID, USED IN THIS FRAMEWORK AS PASSWORD if USER does not provide one
     * @return ID
     */
    protected String getUniquePsuedoID() {
        // If all else fails, if the user does have lower than API 9 (lower
        // than Gingerbread), has reset their device or 'Secure.ANDROID_ID'
        // returns 'null', then simply the ID returned will be solely based
        // off their Android device information. This is where the collisions
        // can happen.
        // Thanks http://www.pocketmagic.net/?p=1662!
        // Try not to use DISPLAY, HOST or ID - these items could change.
        // If there are collisions, there will be overlapping data
        //String m_szDevIDShort = "35" + (Build.BOARD.length() % 10) + (Build.BRAND.length() % 10) + (Build.CPU_ABI.length() % 10) + (Build.DEVICE.length() % 10) + (Build.MANUFACTURER.length() % 10) + (Build.MODEL.length() % 10) + (Build.PRODUCT.length() % 10);
        String m_szDevIDShort = "35" + (Build.BOARD.length() % 10) + (Build.BRAND.length() % 10) +  (Build.DEVICE.length() % 10) + (Build.MANUFACTURER.length() % 10) + (Build.MODEL.length() % 10) + (Build.PRODUCT.length() % 10);
        //String m_szDevIDShort = "my-ID";
        // Thanks to @Roman SL!
        // http://stackoverflow.com/a/4789483/950427
        // Only devices with API >= 9 have android.os.Build.SERIAL
        // http://developer.android.com/reference/android/os/Build.html#SERIAL
        // If a user upgrades software or roots their device, there will be a duplicate entry
        String serial = null;
        try {
            serial = Build.class.getField("SERIAL").get(null).toString();

            // Go ahead and return the serial for api => 9
            String temp = new UUID(m_szDevIDShort.hashCode(), serial.hashCode()).toString();
            //Log.i("UNIQUE-ID:", temp);
            return temp;
        } catch (Exception exception) {
            // String needs to be initialized
            serial = "serial"; // some value
        }

        // Thanks @Joe!
        // http://stackoverflow.com/a/2853253/950427
        // Finally, combine the values we have found by using the UUID class to create a unique identifier
        return new UUID(m_szDevIDShort.hashCode(), serial.hashCode()).toString();
    }

    //Custom Exceptions
    public static class NoAlgorithmAvailableException extends Exception {
        public NoAlgorithmAvailableException (String message) {
            super(message); }
    }
    public static class WrongPasswordException extends Exception {
        public WrongPasswordException (String message) {
            super(message); }
    }
    public static class DataNotAvailableException extends Exception {
        public DataNotAvailableException (String message) {
            super(message); }
    }
    public static class IntegrityCheckFailedException extends Exception {
        public IntegrityCheckFailedException(String message) {
            super(message); }
    }
    public static class NoKeyMaterialException extends Exception {
        public NoKeyMaterialException(String message) {
            super(message);
        }
    }

    /**
     * Class to hold a secretkey and the salt the key was generated with
     */
    protected class SaltAndKey {

        private SecretKey secretKey;
        private byte[] salt;

        protected SaltAndKey (SecretKey secretKey, byte[] salt) {
            this.secretKey = secretKey;
            this.salt = salt;
        }
        protected SecretKey getSecretKey() {
            return secretKey;
        }
        protected byte[] getSalt() {
            return salt;
        }
    }

    /**
     * Checks the performance of the device when running PBKD.
     *
     * @param iterations The iterations used for first performance check
     * @param minIterations Minimum iterations.
     * @return The optimal iteration count for good performance.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    protected long hashPerformanceTest(int iterations, int minIterations) throws NoSuchAlgorithmException, InvalidKeySpecException, NoAlgorithmAvailableException {
        checkPerformanceAlgorithmsLength();
        // Performance check start
        final long startTime = System.currentTimeMillis();
        // Instantiate key specifications with desired parameters
        final byte[] salt = generateRandomBytes(PBE_SALT_LENGTH_BYTE);
        final KeySpec keySpec = new PBEKeySpec("testpassword".toCharArray(), salt, iterations, KEY_LENGTH);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        keyFactory.generateSecret(keySpec).getEncoded();
        // Performance check
        final long stopTime = System.currentTimeMillis();
        final long elapsedTime = stopTime - startTime;
        Log.i("elapsed time", String.valueOf(elapsedTime));
        final long returnIterations = (10000/elapsedTime) * ITERATION_BASE;
        if (minIterations < 1000) {
            minIterations = 1000;
        }
        if (returnIterations < 3*minIterations) {
            return 3*minIterations;
        } else {
            return returnIterations;
        }
    }

    /**
     * Checks whether a suitable algorithm for PBKD is available.
     *
     * @throws CryptoIOHelper.NoAlgorithmAvailableException
     */
    private void checkPerformanceAlgorithmsLength() throws CryptoIOHelper.NoAlgorithmAvailableException {
        final LinkedList<String> algorithms = providerCheck();
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