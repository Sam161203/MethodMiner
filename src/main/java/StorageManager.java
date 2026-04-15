import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

public final class StorageManager implements AutoCloseable {
    private static final Path PREFERRED_LOG_DIRECTORY = Paths.get("D:\\tools\\jsonrpc-logs");

    private static final String RAW_FILE_NAME = "jsonrpc-raw.jsonl";
    private static final String NORMALIZED_FILE_NAME = "jsonrpc-normalized.jsonl";
    private static final String ERROR_FILE_NAME = "jsonrpc-errors.jsonl";
    private static final int FLUSH_EVERY_N_WRITES = 25;

    private final ObjectMapper objectMapper;
    private final Logging logging;

    private final Path projectRoot;
    private final Path dataDirectory;
    private final Path rawPath;
    private final Path normalizedPath;
    private final Path errorPath;

    private final ReentrantLock rawLock = new ReentrantLock();
    private final ReentrantLock normalizedLock = new ReentrantLock();
    private final ReentrantLock errorLock = new ReentrantLock();

    private BufferedWriter rawWriter;
    private BufferedWriter normalizedWriter;
    private BufferedWriter errorWriter;

    private int rawWrites;
    private int normalizedWrites;
    private int errorWrites;

    public StorageManager(String extensionFilename, ObjectMapper objectMapper, Logging logging) {
        this.objectMapper = objectMapper;
        this.logging = logging;

        Path selectedDirectory = resolveWritableLogDirectory();

        this.projectRoot = selectedDirectory;
        this.dataDirectory = selectedDirectory;
        this.rawPath = selectedDirectory.resolve(RAW_FILE_NAME);
        this.normalizedPath = selectedDirectory.resolve(NORMALIZED_FILE_NAME);
        this.errorPath = selectedDirectory.resolve(ERROR_FILE_NAME);

        ensureLogFilesExist();
        this.logging.logToOutput("JSON-RPC logs directory: " + withTrailingSeparator(this.dataDirectory));
    }

    public Path projectRoot() {
        return projectRoot;
    }

    public Path dataDirectory() {
        return dataDirectory;
    }

    public Path rawPath() {
        return rawPath;
    }

    public Path normalizedPath() {
        return normalizedPath;
    }

    public Path errorPath() {
        return errorPath;
    }

    public void appendRaw(JsonRpcRecord record) {
        writeLine(rawPath, rawLock, WriterKind.RAW, toLine(record.toJson(objectMapper)));
    }

    public void appendNormalized(JsonRpcNormalizedRecord record) {
        writeLine(normalizedPath, normalizedLock, WriterKind.NORMALIZED, toLine(record.toJson(objectMapper)));
    }

    public void appendError(ErrorRecord errorRecord) {
        writeLine(errorPath, errorLock, WriterKind.ERROR, toLine(errorRecord.toJson(objectMapper)));
    }

    public void replayRawRecords(RecordReplayListener listener) {
        if (!Files.exists(rawPath)) {
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(rawPath, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                try {
                    JsonNode node = objectMapper.readTree(line);
                    JsonRpcRecord record = JsonRpcRecord.fromJson(node);
                    listener.onRecord(record);
                } catch (Exception ex) {
                    listener.onError(lineNumber, line, ex);
                }
            }
        } catch (IOException ex) {
            logging.logToError("Failed reading raw records for replay.", ex);
        }
    }

    public void resetAll() {
        rawLock.lock();
        normalizedLock.lock();
        errorLock.lock();
        try {
            closeWriterQuietly(rawWriter);
            closeWriterQuietly(normalizedWriter);
            closeWriterQuietly(errorWriter);
            rawWriter = null;
            normalizedWriter = null;
            errorWriter = null;

            recreateLogFile(rawPath);
            recreateLogFile(normalizedPath);
            recreateLogFile(errorPath);

            rawWrites = 0;
            normalizedWrites = 0;
            errorWrites = 0;
        } finally {
            errorLock.unlock();
            normalizedLock.unlock();
            rawLock.unlock();
        }
    }

    @Override
    public void close() {
        rawLock.lock();
        try {
            closeWriter(rawWriter);
            rawWriter = null;
        } finally {
            rawLock.unlock();
        }

        normalizedLock.lock();
        try {
            closeWriter(normalizedWriter);
            normalizedWriter = null;
        } finally {
            normalizedLock.unlock();
        }

        errorLock.lock();
        try {
            closeWriter(errorWriter);
            errorWriter = null;
        } finally {
            errorLock.unlock();
        }
    }

    private Path resolveWritableLogDirectory() {
        Path preferred = normalize(PREFERRED_LOG_DIRECTORY);
        if (canUseDirectory(preferred)) {
            return preferred;
        }

        Path fallback = normalize(Paths.get(System.getProperty("user.home"), "jsonrpc-logs"));
        logging.logToError("Preferred JSON-RPC logs directory is unavailable. Using fallback directory: " + withTrailingSeparator(fallback));
        if (canUseDirectory(fallback)) {
            logging.logToOutput("Using fallback JSON-RPC logs directory: " + withTrailingSeparator(fallback));
            return fallback;
        }

        Path emergency = normalize(Paths.get(System.getProperty("java.io.tmpdir"), "jsonrpc-logs"));
        logging.logToError("Fallback JSON-RPC logs directory is unavailable. Attempting emergency directory: " + withTrailingSeparator(emergency));
        if (canUseDirectory(emergency)) {
            logging.logToOutput("Using emergency JSON-RPC logs directory: " + withTrailingSeparator(emergency));
            return emergency;
        }

        try {
            Path tempDir = Files.createTempDirectory("jsonrpc-logs-").toAbsolutePath().normalize();
            logging.logToError("Using temporary JSON-RPC logs directory due to path initialization failures: " + withTrailingSeparator(tempDir));
            return tempDir;
        } catch (IOException ex) {
            logging.logToError("Unable to create temporary JSON-RPC logs directory. Falling back to user-home path without guarantees.", ex);
            return fallback;
        }
    }

    private boolean canUseDirectory(Path directory) {
        try {
            Files.createDirectories(directory);
            return Files.isDirectory(directory) && Files.isWritable(directory);
        } catch (IOException ex) {
            logging.logToError("Unable to create or access JSON-RPC logs directory at " + withTrailingSeparator(directory), ex);
            return false;
        }
    }

    private void ensureLogFilesExist() {
        try {
            Files.createDirectories(dataDirectory);
            ensureExists(rawPath);
            ensureExists(normalizedPath);
            ensureExists(errorPath);

            assertWritable(dataDirectory, "logs directory");
            assertWritable(rawPath, "raw log file");
            assertWritable(normalizedPath, "normalized log file");
            assertWritable(errorPath, "error log file");
        } catch (IOException ex) {
            logging.logToError("Unable to initialize JSON-RPC log files in " + withTrailingSeparator(dataDirectory), ex);
        }
    }

    private static void ensureExists(Path path) throws IOException {
        if (Files.exists(path)) {
            if (!Files.isRegularFile(path)) {
                throw new IOException("Expected a regular file at " + path + " but found a different file type.");
            }
            return;
        }
        Files.createFile(path);
    }

    private static void assertWritable(Path path, String label) throws IOException {
        if (!Files.isWritable(path)) {
            throw new IOException("The " + label + " is not writable: " + path);
        }
    }

    private void writeLine(Path path, ReentrantLock lock, WriterKind kind, String line) {
        lock.lock();
        try {
            BufferedWriter writer = writer(kind, path);
            writer.write(line);
            writer.newLine();
            maybeFlush(kind, writer);
        } catch (IOException ex) {
            logging.logToError("Failed appending to " + path, ex);
        } finally {
            lock.unlock();
        }
    }

    private BufferedWriter writer(WriterKind kind, Path path) throws IOException {
        return switch (kind) {
            case RAW -> {
                if (rawWriter == null) {
                    rawWriter = openAppendWriter(path);
                }
                yield rawWriter;
            }
            case NORMALIZED -> {
                if (normalizedWriter == null) {
                    normalizedWriter = openAppendWriter(path);
                }
                yield normalizedWriter;
            }
            case ERROR -> {
                if (errorWriter == null) {
                    errorWriter = openAppendWriter(path);
                }
                yield errorWriter;
            }
        };
    }

    private void maybeFlush(WriterKind kind, BufferedWriter writer) throws IOException {
        switch (kind) {
            case RAW -> {
                rawWrites++;
                if (rawWrites >= FLUSH_EVERY_N_WRITES) {
                    writer.flush();
                    rawWrites = 0;
                }
            }
            case NORMALIZED -> {
                normalizedWrites++;
                if (normalizedWrites >= FLUSH_EVERY_N_WRITES) {
                    writer.flush();
                    normalizedWrites = 0;
                }
            }
            case ERROR -> {
                errorWrites++;
                if (errorWrites >= FLUSH_EVERY_N_WRITES) {
                    writer.flush();
                    errorWrites = 0;
                }
            }
        }
    }

    private static BufferedWriter openAppendWriter(Path path) throws IOException {
        return Files.newBufferedWriter(
                path,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        );
    }

    private static String toLine(JsonNode node) {
        return node.toString();
    }

    private void recreateLogFile(Path path) {
        try {
            Files.deleteIfExists(path);
            Files.createFile(path);
        } catch (IOException ex) {
            logging.logToError("Unable to recreate JSON-RPC log file at " + path, ex);
        }
    }

    private static void closeWriter(BufferedWriter writer) {
        if (writer == null) {
            return;
        }
        try {
            writer.flush();
            writer.close();
        } catch (IOException ignored) {
            // Ignore during shutdown.
        }
    }

    private static void closeWriterQuietly(BufferedWriter writer) {
        if (writer == null) {
            return;
        }
        try {
            writer.close();
        } catch (IOException ignored) {
            // Ignore while resetting writers.
        }
    }

    private static Path normalize(Path path) {
        return path.toAbsolutePath().normalize();
    }

    private static String withTrailingSeparator(Path path) {
        String text = path.toAbsolutePath().normalize().toString();
        if (text.endsWith("\\") || text.endsWith("/")) {
            return text;
        }
        return text + "\\";
    }

    private enum WriterKind {
        RAW,
        NORMALIZED,
        ERROR
    }

    public interface RecordReplayListener {
        void onRecord(JsonRpcRecord record);

        void onError(int lineNumber, String lineContent, Exception exception);
    }

    public record ErrorRecord(
            Instant timestamp,
            Integer messageId,
            String url,
            String category,
            String detail,
            String requestBodySnippet
    ) {
        public ObjectNode toJson(ObjectMapper mapper) {
            ObjectNode node = mapper.createObjectNode();
            node.put("timestamp", (timestamp == null ? Instant.now() : timestamp).toString());
            if (messageId == null) {
                node.putNull("messageId");
            } else {
                node.put("messageId", messageId);
            }
            node.put("url", url == null ? "" : url);
            node.put("category", category == null ? "unknown" : category);
            node.put("detail", detail == null ? "" : detail);
            node.put("requestBodySnippet", requestBodySnippet == null ? "" : requestBodySnippet);
            return node;
        }
    }
}
