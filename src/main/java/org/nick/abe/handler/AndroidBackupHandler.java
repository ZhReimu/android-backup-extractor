package org.nick.abe.handler;

import java.io.InputStream;
import java.io.OutputStream;

public class AndroidBackupHandler extends BaseBackupHandler {

    @Override
    public void extractAsTar(String backupFilename, String filename, String password) {
        try {
            BackupFileMeta backupFileMeta = BackupFileMeta.of(backupFilename, password);
            if (backupFileMeta.isEncrypted() && backupFileMeta.getCipherStream() == null) {
                throw new IllegalStateException("Invalid password or master key checksum.");
            }
            double percentDone = -1;
            try (InputStream in = backupFileMeta.getWorkInputStream(); OutputStream out = getOutputStream(filename)) {
                byte[] buff = new byte[10 * 1024];
                int read;
                long totalRead = 0; // of the input file decompressed
                while ((read = in.read(buff)) > 0) {
                    out.write(buff, 0, read);
                    totalRead += read;
                    if (totalRead % 100 * 1024 == 0) {
                        logger.debug("{} bytes read", totalRead);
                    }
                    //Log the percentage extracted of the input file compressed
                    long bytesRead = backupFileMeta.getInf() == null ? totalRead : backupFileMeta.getInf().getBytesRead();
                    // of the input file
                    double currentPercent = Math.round(bytesRead / backupFileMeta.getFileSize() * 100);
                    if (currentPercent != percentDone) {
                        logger.info(String.format("%.0f%% ", currentPercent));
                        percentDone = currentPercent;
                    }
                }
                logger.info("{} bytes written to {}.", totalRead, filename);
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * 将文件打包成备份文件
     *
     * @param tarFilename    要打包的文件名
     * @param backupFilename 打包后的文件名
     * @param meta           打包参数
     */
    @Override
    protected void packTar(String tarFilename, String backupFilename, PackBackupFileMeta meta) {
        StringBuilder headerBuf = new StringBuilder(1024);
        // TODO: 添加 MIUI 文件头
        //MIUI BACKUP
        //2
        //<包名> <app 名称>
        //-1
        //0
        headerBuf.append(BACKUP_FILE_HEADER_MAGIC);
        // integer, no trailing \n
        headerBuf.append(meta.isKitKat() ? BACKUP_FILE_V2 : BACKUP_FILE_V1);
        headerBuf.append(meta.isCompressing() ? "\n1\n" : "\n0\n");
        try (InputStream in = getInputStream(tarFilename); OutputStream out = meta.getOutputStream(headerBuf)) {
            byte[] buff = new byte[10 * 1024];
            int read;
            int totalRead = 0;
            while ((read = in.read(buff)) > 0) {
                out.write(buff, 0, read);
                totalRead += read;
                if (totalRead % 100 * 1024 == 0) {
                    logger.debug("{} bytes written", totalRead);
                }
            }
            logger.info("packTar: {} bytes written to {}.", totalRead, backupFilename);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
