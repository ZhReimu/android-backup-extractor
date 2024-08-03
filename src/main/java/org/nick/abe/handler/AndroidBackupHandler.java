package org.nick.abe.handler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

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

    @Override
    public void packTar(String tarFilename, String backupFilename, String password, boolean isKitKat) {
        boolean encrypting = password != null && !password.isEmpty();
        boolean compressing = true;
        StringBuilder headerbuf = new StringBuilder(1024);
        headerbuf.append(BACKUP_FILE_HEADER_MAGIC);
        // integer, no trailing \n
        headerbuf.append(isKitKat ? BACKUP_FILE_V2 : BACKUP_FILE_V1);
        headerbuf.append(compressing ? "\n1\n" : "\n0\n");
        OutputStream out = null;
        try {
            InputStream in = getInputStream(tarFilename);
            OutputStream ofstream = getOutputStream(backupFilename);
            OutputStream finalOutput = ofstream;
            // Set up the encryption stage if appropriate, and emit the correct
            // header
            if (encrypting) {
                finalOutput = emitAesBackupHeader(headerbuf, finalOutput, password, isKitKat);
            } else {
                headerbuf.append("none\n");
            }
            byte[] header = headerbuf.toString().getBytes(StandardCharsets.UTF_8);
            ofstream.write(header);
            // Set up the compression stage feeding into the encryption stage
            // (if any)
            if (compressing) {
                Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
                // requires Java 7
                finalOutput = new DeflaterOutputStream(finalOutput, deflater, true);
            }
            out = finalOutput;
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
        } finally {
            if (out != null) {
                try {
                    out.flush();
                    out.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

}
