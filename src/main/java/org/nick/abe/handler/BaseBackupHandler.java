package org.nick.abe.handler;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * @author Mr.X
 * @since 2024/8/3 下午2:30
 */
public abstract class BaseBackupHandler {

    protected static final int BACKUP_MANIFEST_VERSION = 1;

    protected static final String BACKUP_FILE_HEADER_MAGIC = "ANDROID BACKUP\n";

    protected static final String MIUI_BACKUP_FILE_HEADER = "MIUI BACKUP";

    protected static final int BACKUP_FILE_V1 = 1;

    protected static final int BACKUP_FILE_V2 = 2;

    protected static final int BACKUP_FILE_V3 = 3;

    protected static final int BACKUP_FILE_V4 = 4;

    protected static final int BACKUP_FILE_V5 = 5;

    protected static final String ENCRYPTION_MECHANISM = "AES/CBC/PKCS5Padding";

    protected static final int PBKDF2_HASH_ROUNDS = 10000;

    protected static final int PBKDF2_KEY_SIZE = 256; // bits

    protected static final int MASTER_KEY_SIZE = 256; // bits

    protected static final int PBKDF2_SALT_SIZE = 512; // bits

    protected static final String ENCRYPTION_ALGORITHM_NAME = "AES-256";

    protected static final SecureRandom random = new SecureRandom();

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private static final Logger thisLogger = LoggerFactory.getLogger(BaseBackupHandler.class);

    /**
     * 将文件当作 tar 解包
     *
     * @param backupFilename 备份文件名
     * @param filename       解包后的文件名
     * @param password       备份密码
     */
    public abstract void extractAsTar(String backupFilename, String filename, String password);

    /**
     * 将文件打包成备份文件
     *
     * @param tarFilename    要打包的文件
     * @param backupFilename 打包后的文件名
     * @param password       加密密码
     * @param isKitKat       是否为 Android 4.4
     */
    public abstract void packTar(String tarFilename, String backupFilename, String password, boolean isKitKat);

    protected static InputStream getInputStream(String filename) throws IOException {
        if (filename.equals("-")) {
            return System.in;
        } else {
            return new FileInputStream(filename);
        }
    }

    protected OutputStream getOutputStream(String filename) throws IOException {
        if (filename.equals("-")) {
            return System.out;
        }
        // TODO: 换回来
        // return new FileOutputStream(filename);
        return new ByteArrayOutputStream();
    }

    protected byte[] randomBytes(int bits) {
        byte[] array = new byte[bits / 8];
        random.nextBytes(array);
        return array;
    }

    protected OutputStream emitAesBackupHeader(StringBuilder buf, OutputStream os, String encryptionPassword, boolean useUtf8) throws Exception {
        // User key will be used to encrypt the master key.
        byte[] newUserSalt = randomBytes(PBKDF2_SALT_SIZE);
        SecretKey userKey = buildPasswordKey(encryptionPassword, newUserSalt, PBKDF2_HASH_ROUNDS, useUtf8);
        // the master key is random for each backup
        byte[] masterPw = new byte[MASTER_KEY_SIZE / 8];
        random.nextBytes(masterPw);
        byte[] checksumSalt = randomBytes(PBKDF2_SALT_SIZE);
        // primary encryption of the datastream with the random key
        Cipher c = Cipher.getInstance(ENCRYPTION_MECHANISM);
        SecretKeySpec masterKeySpec = new SecretKeySpec(masterPw, "AES");
        c.init(Cipher.ENCRYPT_MODE, masterKeySpec);
        OutputStream finalOutput = new CipherOutputStream(os, c);
        // line 4: name of encryption algorithm
        buf.append(ENCRYPTION_ALGORITHM_NAME);
        buf.append('\n');
        // line 5: user password salt [hex]
        buf.append(toHex(newUserSalt));
        buf.append('\n');
        // line 6: master key checksum salt [hex]
        buf.append(toHex(checksumSalt));
        buf.append('\n');
        // line 7: number of PBKDF2 rounds used [decimal]
        buf.append(PBKDF2_HASH_ROUNDS);
        buf.append('\n');
        // line 8: IV of the user key [hex]
        Cipher mkC = Cipher.getInstance(ENCRYPTION_MECHANISM);
        mkC.init(Cipher.ENCRYPT_MODE, userKey);
        byte[] IV = mkC.getIV();
        buf.append(toHex(IV));
        buf.append('\n');
        // line 9: master IV + key blob, encrypted by the user key [hex]. Blob
        // format:
        // [byte] IV length = Niv
        // [array of Niv bytes] IV itself
        // [byte] master key length = Nmk
        // [array of Nmk bytes] master key itself
        // [byte] MK checksum hash length = Nck
        // [array of Nck bytes] master key checksum hash
        //
        // The checksum is the (master key + checksum salt), run through the
        // stated number of PBKDF2 rounds
        IV = c.getIV();
        byte[] mk = masterKeySpec.getEncoded();
        byte[] checksum = makeKeyChecksum(masterKeySpec.getEncoded(), checksumSalt, PBKDF2_HASH_ROUNDS, useUtf8);
        ByteArrayOutputStream blob = new ByteArrayOutputStream(IV.length + mk.length + checksum.length + 3);
        DataOutputStream mkOut = new DataOutputStream(blob);
        mkOut.writeByte(IV.length);
        mkOut.write(IV);
        mkOut.writeByte(mk.length);
        mkOut.write(mk);
        mkOut.writeByte(checksum.length);
        mkOut.write(checksum);
        mkOut.flush();
        byte[] encryptedMk = mkC.doFinal(blob.toByteArray());
        buf.append(toHex(encryptedMk));
        buf.append('\n');
        return finalOutput;
    }

    protected static String toHex(byte[] bytes) {
        StringBuilder buff = new StringBuilder();
        for (byte b : bytes) {
            buff.append(String.format("%02X", b));
        }
        return buff.toString();
    }

    protected static String readHeaderLine(InputStream in) throws IOException {
        int c;
        StringBuilder buffer = new StringBuilder(80);
        while ((c = in.read()) >= 0) {
            if (c == '\n')
                break; // consume and discard the newlines
            buffer.append((char) c);
        }
        // ignore miui backup header
        String result = buffer.toString();
        if (result.equals(MIUI_BACKUP_FILE_HEADER)) {
            // skip next 5 \n
            for (int i = 0; i < 4; i++) {
                readHeaderLine(in);
            }
            result = readHeaderLine(in);
        }
        return result;
    }

    public static byte[] hexToByteArray(String digits) {
        final int bytes = digits.length() / 2;
        if (2 * bytes != digits.length()) {
            throw new IllegalArgumentException("Hex string must have an even number of digits");
        }
        byte[] result = new byte[bytes];
        for (int i = 0; i < digits.length(); i += 2) {
            result[i / 2] = (byte) Integer.parseInt(digits.substring(i, i + 2), 16);
        }
        return result;
    }

    public static byte[] makeKeyChecksum(byte[] pwBytes, byte[] salt, int rounds, boolean useUtf8) {
        thisLogger.debug("key bytes: {}", toHex(pwBytes));
        thisLogger.debug("salt bytes: {}", toHex(salt));
        char[] mkAsChar = new char[pwBytes.length];
        for (int i = 0; i < pwBytes.length; i++) {
            mkAsChar[i] = (char) pwBytes[i];
        }
        thisLogger.debug("MK as string: [{}]", new String(mkAsChar));
        Key checksum = buildCharArrayKey(mkAsChar, salt, rounds, useUtf8);
        thisLogger.debug("Key format: {}", checksum.getFormat());
        return checksum.getEncoded();
    }

    public static SecretKey buildCharArrayKey(char[] pwArray, byte[] salt, int rounds, boolean useUtf8) {
        // Original code from BackupManagerService
        // this produces different results when run with Sun/Oracale Java SE
        // which apparently treats password bytes as UTF-8 (16?)
        // (the encoding is left unspecified in PKCS#5)

        // try {
        // SecretKeyFactory keyFactory = SecretKeyFactory
        // .getInstance("PBKDF2WithHmacSHA1");
        // KeySpec ks = new PBEKeySpec(pwArray, salt, rounds, PBKDF2_KEY_SIZE);
        // return keyFactory.generateSecret(ks);
        // } catch (InvalidKeySpecException e) {
        // throw new RuntimeException(e);
        // } catch (NoSuchAlgorithmException e) {
        // throw new RuntimeException(e);
        // } catch (NoSuchProviderException e) {
        // throw new RuntimeException(e);
        // }
        // return null;

        return androidPBKDF2(pwArray, salt, rounds, useUtf8);
    }

    public static SecretKey androidPBKDF2(char[] pwArray, byte[] salt, int rounds, boolean useUtf8) {
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
        // Android treats password bytes as ASCII, which is obviously
        // not the case when an AES key is used as a 'password'.
        // Use the same method for compatibility.

        // Android 4.4 however uses all char bytes
        // useUtf8 needs to be true for KitKat
        byte[] pwBytes = useUtf8 ? PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(pwArray)
                : PBEParametersGenerator.PKCS5PasswordToBytes(pwArray);
        generator.init(pwBytes, salt, rounds);
        KeyParameter params = (KeyParameter) generator.generateDerivedParameters(PBKDF2_KEY_SIZE);
        return new SecretKeySpec(params.getKey(), "AES");
    }

    protected static SecretKey buildPasswordKey(String pw, byte[] salt, int rounds, boolean useUtf8) {
        return buildCharArrayKey(pw.toCharArray(), salt, rounds, useUtf8);
    }

    protected static boolean isDigit(String s) {
        if (s == null || s.isBlank()) {
            return false;
        }
        return s.chars().allMatch(Character::isDigit);
    }

    private static CipherInputStream getCipherInputStream(InputStream ins, BackupFileMeta meta) throws Exception {
        if (!meta.isEncrypted) {
            return null;
        }
        if (Cipher.getMaxAllowedKeyLength("AES") < MASTER_KEY_SIZE) {
            thisLogger.debug("WARNING: Maximum allowed key-length seems smaller than needed. " +
                    "Please check that unlimited strength cryptography is available, see README.md for details");
        }
        if (meta.password == null || meta.password.isEmpty()) {
            Console console = System.console();
            if (console != null) {
                thisLogger.debug("This backup is encrypted, please provide the password");
                meta.password = new String(console.readPassword("Password: "));
            } else {
                throw new IllegalArgumentException("Backup encrypted but password not specified");
            }
        }
        String userSaltHex = readHeaderLine(ins); // 5
        byte[] userSalt = hexToByteArray(userSaltHex);
        if (userSalt.length != PBKDF2_SALT_SIZE / 8) {
            throw new IllegalArgumentException("Invalid salt length: " + userSalt.length);
        }
        String ckSaltHex = readHeaderLine(ins); // 6
        byte[] ckSalt = hexToByteArray(ckSaltHex);
        int rounds = Integer.parseInt(readHeaderLine(ins)); // 7
        String userIvHex = readHeaderLine(ins); // 8
        String masterKeyBlobHex = readHeaderLine(ins); // 9
        // decrypt the master key blob
        Cipher c = Cipher.getInstance(ENCRYPTION_MECHANISM);
        // XXX we don't support non-ASCII passwords
        SecretKey userKey = buildPasswordKey(meta.password, userSalt, rounds, false);
        byte[] IV = hexToByteArray(userIvHex);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(userKey.getEncoded(), "AES"), ivSpec);
        byte[] mkCipher = hexToByteArray(masterKeyBlobHex);
        byte[] mkBlob = c.doFinal(mkCipher);
        // first, the master key IV
        int offset = 0;
        int len = mkBlob[offset++];
        IV = Arrays.copyOfRange(mkBlob, offset, offset + len);
        thisLogger.debug("IV: {}", toHex(IV));
        offset += len;
        // then the master key itself
        len = mkBlob[offset++];
        byte[] mk = Arrays.copyOfRange(mkBlob, offset, offset + len);
        thisLogger.debug("MK: {}", toHex(mk));
        offset += len;
        // and finally the master key checksum hash
        len = mkBlob[offset++];
        byte[] mkChecksum = Arrays.copyOfRange(mkBlob, offset, offset + len);
        thisLogger.debug("MK checksum: {}", toHex(mkChecksum));
        // now validate the decrypted master key against the checksum
        // first try the algorithm matching the archive version
        boolean useUtf = meta.version >= BACKUP_FILE_V2;
        byte[] calculatedCk = makeKeyChecksum(mk, ckSalt, rounds, useUtf);
        System.err.printf("Calculated MK checksum (use UTF-8: %s): %s\n", useUtf, toHex(calculatedCk));
        if (!Arrays.equals(calculatedCk, mkChecksum)) {
            thisLogger.debug("Checksum does not match.");
            // try the reverse
            calculatedCk = makeKeyChecksum(mk, ckSalt, rounds, !useUtf);
            System.err.printf("Calculated MK checksum (use UTF-8: %s): %s\n", useUtf, toHex(calculatedCk));
        }
        if (Arrays.equals(calculatedCk, mkChecksum)) {
            ivSpec = new IvParameterSpec(IV);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(mk, "AES"), ivSpec);
            // Only if all of the above worked properly will 'result' be assigned
            return new CipherInputStream(ins, c);
        }
        return null;
    }

    protected static class BackupFileMeta {
        private InputStream rawInStream;
        private CipherInputStream cipherStream;
        private String magic;
        private int version;
        private boolean isCompressed;
        private boolean isEncrypted;
        private long fileSize;
        private String password;
        private InputStream baseStream;
        private Inflater inf;
        private InputStream workInputStream;

        public static BackupFileMeta of(String fileName, String password) throws Exception {
            BackupFileMeta result = new BackupFileMeta();
            InputStream rawInStream = getInputStream(fileName);
            // To prevent the NumberFormatException when trying to figure out the backup version
            long size = Files.size(Paths.get(fileName));
            if (size == 0) {
                throw new IllegalStateException("File too small in size");
            }
            String magic = readHeaderLine(rawInStream); // 1
            String versionStr = readHeaderLine(rawInStream); // 2
            if (!isDigit(versionStr)) {
                throw new IllegalArgumentException("Invalid version: " + Hex.toHexString(versionStr.getBytes(StandardCharsets.UTF_8)));
            }
            int version = Integer.parseInt(versionStr);
            if (version < BACKUP_FILE_V1 || version > BACKUP_FILE_V5) {
                throw new IllegalArgumentException("Don't know how to process version " + versionStr);
            }
            String compressed = readHeaderLine(rawInStream); // 3
            if (!isDigit(compressed)) {
                throw new IllegalArgumentException("Invalid param " + compressed);
            }
            boolean isCompressed = Integer.parseInt(compressed) == 1;
            String encryptionAlg = readHeaderLine(rawInStream); // 4
            result.magic = magic;
            result.version = version;
            result.isCompressed = isCompressed;
            result.isEncrypted = encryptionAlg.equals(ENCRYPTION_ALGORITHM_NAME);
            result.rawInStream = rawInStream;
            //Get input file size for percentage printing
            result.fileSize = size;
            result.password = password;
            result.baseStream = result.isEncrypted ? result.cipherStream : rawInStream;
            result.cipherStream = getCipherInputStream(rawInStream, result);
            if (isCompressed) {
                // The Inflater is needed to get the correct percentage because of compression
                result.inf = new Inflater();
                result.workInputStream = new InflaterInputStream(result.baseStream, result.inf);
            } else {
                result.workInputStream = result.baseStream;
            }
            return result;
        }

        public InputStream getRawInStream() {
            return rawInStream;
        }

        public CipherInputStream getCipherStream() {
            return cipherStream;
        }

        public String getMagic() {
            return magic;
        }

        public int getVersion() {
            return version;
        }

        public boolean isCompressed() {
            return isCompressed;
        }

        public boolean isEncrypted() {
            return isEncrypted;
        }

        public double getFileSize() {
            return fileSize;
        }

        public String getPassword() {
            return password;
        }

        public InputStream getBaseStream() {
            return baseStream;
        }

        public InputStream getWorkInputStream() {
            return workInputStream;
        }

        public Inflater getInf() {
            return inf;
        }
    }

}
