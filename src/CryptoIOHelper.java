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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class CryptoIOHelper {

    // Context
    private Context context;
    // Exception messages
    private final static String DATA_NOT_AVAILABLE = "Data not available";
    // Message if no suitable algorithm available
    private static final String NO_ALG_MSG = "No algorithm available on this platform";
    // Variables for performance test
    private static String PBE_ALGORITHM;
    //private static int PBE_ITERATIONS;
    private static final int PBE_SALT_LENGTH_BYTE = 64;
    private static final int KEY_LENGTH = 256;
    //private static final int PERFORMANCE_CHECK = 1000;
    private static final int ITERATION_BASE = 100;
    // For logging
    private static final String TAG = CryptoIOHelper.class.getSimpleName();
    private static final String EXC = "Exception";

    /**
     * Constructor, sets the context.
     * @param context the context
     */
    public CryptoIOHelper(Context context) {
        this.context = context;
        // Apply Googles pseudo random number generator fix
        fixPrng();
        //For performance test
    }

    /**
     * Encodes the given byte array to a Base64 byted array
     * @param data  the byte array to be encoded
     * @return      the encoded byte array
     */
    public byte[] encodeToBase64(byte[] data) {
        return Base64.encode(data, Base64.NO_WRAP);
    }

    /**
     * Encodes the given byte array to a Base64-String
     * @param data  the byte array to be encoded
     * @return      the encoded String
     */
    public String encodeToBase64String(byte[] data) {
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    /**
     * Decodes the given Base64-encoded byte array
     * @param data      the Base64-encoded byte array
     * @return          the decoded data as byte array
     */
    public byte[] decodeBase64(byte[] data) {
        return Base64.decode(data, Base64.NO_WRAP);
    }

    /**
     * Decodes the given Base64-encoded String
     * @param data      the Base64-encoded String
     * @return          the decoded data as byte array
     */
    public byte[] decodeBase64String(String data) {
        return Base64.decode(data, Base64.NO_WRAP);
    }

    /**
     * Deletes the specified file.
     * @param filename  The filename to be deleted.
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    public void deleteFile  (String filename) throws DataNotAvailableException {
        final String dir = context.getFilesDir().getAbsolutePath();
        final File file = new File(dir, filename);
        final boolean deleted = file.delete();
        if (!deleted) {
            throw new DataNotAvailableException(DATA_NOT_AVAILABLE);
        }
    }

    /**
     * Deletes the specified SharedPref file.
     * @param alias     The alias for the SharedPref to be deleted.
     */
    public void deleteSharedPref(String alias) {
        final SharedPreferences sharedPreferences = context.getSharedPreferences(alias, Context.MODE_PRIVATE);
        final SharedPreferences.Editor spEditor = sharedPreferences.edit();
        spEditor.clear();
        spEditor.apply();
    }

    /**
     * Deletes the alias from specified SharedPref file.
     * @param spAlias   The SharedPreferences alias
     * @param alias     The alias for the file to be deleted.
     */
    public void deleteFromSharedPref(String spAlias, String alias) {
        final SharedPreferences sharedPreferences = context.getSharedPreferences(spAlias, Context.MODE_PRIVATE);
        final SharedPreferences.Editor spEditor = sharedPreferences.edit();
        spEditor.remove(alias);
        spEditor.apply();
    }

    /**
     * Saves byte array to the specified file in the app folder, encodes the bytes to Base64
     * before writing. The file will only be accessible to your app.
     * @param filename      the filename under which the data should be stored
     * @param write         the data to be stored
     * @throws IOException
     */
    public void saveBytesToFileBase64(String filename, byte[] write) throws IOException {
        final FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE);
        fos.write(this.encodeToBase64(write));
        fos.close();
    }

    /**
     * Reads a formerly saved byte array from the given file in the app folder,
     * must have been Base64-encoded
     * @param filename      the filename
     * @return              the data as byte array
     * @throws IOException
     */
    public byte[] readBytesFromFileBase64(String filename) throws IOException {
        final FileInputStream fis = context.openFileInput(filename);
        final byte [] buffer = new byte[(int) fis.getChannel().size()];
        fis.read(buffer);
        fis.close();
        return this.decodeBase64(buffer);
    }

    /**
     * Saves data as Base64-encoded String in the app's SharedPreferences. Will only
     * be accessible by your app.
     * @param spAlias     the alias under which the SharedPref is to be stored
     * @param dataAlias   the alias of the data itself
     * @param data        the data as byte array
     */
    public void saveToSharedPrefBase64(String spAlias, String dataAlias, byte[] data) {
        final SharedPreferences sharedPreferences = context.getSharedPreferences(spAlias, Context.MODE_PRIVATE);
        final SharedPreferences.Editor spEditor = sharedPreferences.edit();
        spEditor.putString(dataAlias, this.encodeToBase64String(data));
        spEditor.apply();
    }

    /**
     * Reads the data saved under the specified alias. Data must have been saved
     * Base64-encoded.
     * @param spAlias       the alias under which the SharePref was stored
     * @param dataAlias     the alias of the data itself
     * @return              the data as byte array
     * @throws CryptoIOHelper.DataNotAvailableException
     */
    public byte[] loadFromSharedPrefBase64(String spAlias, String dataAlias) throws DataNotAvailableException {
            final SharedPreferences sharedPreferences = context.getSharedPreferences(spAlias, Context.MODE_PRIVATE);
            String temp = sharedPreferences.getString(dataAlias, null);
            if (temp != null) {
                return this.decodeBase64String(temp);
            } else {
                throw new DataNotAvailableException(DATA_NOT_AVAILABLE);
            }
    }

    /**
     * Method for Debugging Purposes. Checks which Cryptographic Providers are available
     * on the present platform. Returns a LinkedList with the algorithms that are available
     * on the present Platform.
     */
    public LinkedList<String> providerCheck() {
        // List all providers
        LinkedList<String> algorithmList = new LinkedList<String>();
        final Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
//            Log.i("CRYPTO", "provider: " + provider.getName());
            final Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                //if (provider.getName().equalsIgnoreCase("AndroidOpenSSL"))
//                Log.i("CRYPTO", "  algorithm: " + service.getAlgorithm());
                algorithmList.add(service.getAlgorithm());
            }
        }
        return algorithmList;
    }

    /**
     * Generates a random byte array that can be used as a salt or for any
     * other similar purpose.
     * @param length    the desired length of the salt (array) in byte
     * @return          the byte array, length bytes long
     */
    public byte[] generateRandomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] random = new byte[length];
        secureRandom.nextBytes(random);
        return random;
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     */
    private static void fixPrng() {
        synchronized (PRNGFixes.class) {
           PRNGFixes.apply();
        }
    }

    /**
     * Return pseudo unique ID, USED IN THIS FRAMEWORK AS PASSWORD if USER does not provide one
     * @return ID
     */
    public String getUniquePsuedoID() {
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
        public NoAlgorithmAvailableException (String message) { super(message); }
    }
    public static class WrongModeException extends Exception{
        public WrongModeException (String message) { super(message); }
    }
    public static class WrongPasswordException extends Exception {
        public WrongPasswordException (String message) { super(message); }
    }
    public static class DataNotAvailableException extends Exception {
        public DataNotAvailableException (String message) { super(message); }
    }
    public static class IntegrityCheckFailedException extends Exception {
        public IntegrityCheckFailedException(String message) { super(message); }
    }

    /**
     * Class to hold a secretkey and the salt the key was generated with
     */
    public class SaltAndKey {

        private SecretKey secretKey;
        private byte[] salt;

        public SaltAndKey (SecretKey secretKey, byte[] salt) {
            this.secretKey = secretKey;
            this.salt = salt;
        }
        public SecretKey getSecretKey() {
            return secretKey;
        }
        public byte[] getSalt() {
            return salt;
        }
    }


    // Bisher nicht benötigt

    /**
     * Saves byte array to specified file in the app-folder. The file will only be accessible
     * by your app.
     * @param filename      the filename
     * @param write         data to be saved
     * @throws IOException
     */
    public void saveBytesToFile(String filename, byte[] write) throws IOException {
        final FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE);
        fos.write(write);
        fos.close();
    }

    /**
     * Reads a formerly saved byte array from the given file in the app folder
     * @param filename      the filename
     * @return              the data as byte array
     * @throws IOException
     */
    public byte[] readBytesFromFile(String filename) throws IOException {
        final FileInputStream fis = context.openFileInput(filename);
        final byte [] buffer = new byte[(int) fis.getChannel().size()];
        fis.read(buffer);
        fis.close();
        return buffer;
    }

    /**
     * Checks the performance of the device when running PBKD.
     * @param iterations The iteraions.
     * @return  True if a certain threshhold (PERFORMANCE_CHECK) has been eclipsed, False otherwise.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public long hashPerformanceTest(int iterations) throws NoSuchAlgorithmException, InvalidKeySpecException, NoAlgorithmAvailableException {
        checkPerformanceAlgorithmsLength();
        // Performance check start
        final long startTime = System.currentTimeMillis();
        // Instantiate key specifications with desired parameters
        final byte[] salt = generateRandomBytes(PBE_SALT_LENGTH_BYTE);
        final KeySpec keySpec = new PBEKeySpec("testpassword".toCharArray(), salt, iterations, KEY_LENGTH);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        final byte[] temp = keyFactory.generateSecret(keySpec).getEncoded();
        // Performance check
        final long stopTime = System.currentTimeMillis();
        final long elapsedTime = stopTime - startTime;
        return (10000/elapsedTime) * ITERATION_BASE;
    }

    /**
     * Checks whether a suitable algorithm for PBKD is available.
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
}