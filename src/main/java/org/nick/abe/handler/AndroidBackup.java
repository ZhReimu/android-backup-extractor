package org.nick.abe.handler;

/**
 * @author Mr.X
 * @since 2024/8/3 下午2:40
 */
public class AndroidBackup {

    private static final BaseBackupHandler ANDROID_BACKUP_HANDLER = new AndroidBackupHandler();

    public static void extractAsTar(String backupFilename, String tarFilename, String password) {
        ANDROID_BACKUP_HANDLER.extractAsTar(backupFilename, tarFilename, password);
    }

    public static void packTar(String tarFilename, String backupFilename, String password, boolean isKitKat) {
        ANDROID_BACKUP_HANDLER.packTar(tarFilename, backupFilename, password, isKitKat, true, false);
    }
}
