import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import parcs.*;

public class HashCracker implements AM {

    // Configuration (same as Python version)
    private static final String CHAR_SET = "abcdefghijklmnopqrstuvwxyz";
    private static final int MIN_LEN = 1;
    private static int MAX_LEN = 6;

    private static long startTime = 0;

    // ================= TIMER =================

    public static void startTimer() {
        startTime = System.nanoTime();
    }

    public static double stopTimer() {
        long endTime = System.nanoTime();
        return (endTime - startTime) / 1_000_000_000.0;
    }

    // ================= MAIN =================

    public static void main(String[] args) throws Exception {

        if (args.length != 3) {
            System.err.println("Usage: HashCracker <number-of-workers> <secret> <max-len>");
            System.exit(1);
        }

        int k = Integer.parseInt(args[0]);
        String secret = args[1];
        MAX_LEN = Integer.parseInt(args[2]);
        String targetHash = sha256(secret);

        long totalKeyspace = calculateKeyspaceSize();

        System.out.println("Target Hash: " + targetHash);
        System.out.println("Total keyspace: " + totalKeyspace);

        task curtask = new task();
        curtask.addJarFile("HashCracker.jar");
        AMInfo info = new AMInfo(curtask, null);

        startTimer();

        channel[] channels = new channel[k];

        long keysPerWorker = totalKeyspace / k;
        long remainder = totalKeyspace % k;

        long startIndex = 0;

        for (int i = 0; i < k; i++) {

            long rangeSize = keysPerWorker + (i < remainder ? 1 : 0);
            long endIndex = startIndex + rangeSize;

            point p = info.createPoint();
            channel c = p.createChannel();
            p.execute("HashCracker");

            c.write(targetHash);
            c.write(Long.valueOf(startIndex));
            c.write(Long.valueOf(endIndex));

            channels[i] = c;

            startIndex = endIndex;
        }

        String foundKey = null;

        for (int i = 0; i < k; i++) {
            Object result = channels[i].readObject();
            if (result != null) {
                foundKey = (String) result;
            }
        }

        double time = stopTimer();

        if (foundKey != null)
            System.out.println("Found key: " + foundKey);
        else
            System.out.println("Key not found.");

        System.out.println("Execution time: " + time + " seconds");

        curtask.end();
    }

    // ================= WORKER =================

    public void run(AMInfo info) {

        String targetHash = (String) info.parent.readObject();
        long startIndex = (Long) info.parent.readObject();
        long endIndex = (Long) info.parent.readObject();

        String result = crackRange(targetHash, startIndex, endIndex);

        info.parent.write(result);
    }

    // ================= CORE LOGIC =================

    public static String crackRange(String targetHash, long startIndex, long endIndex) {

        int base = CHAR_SET.length();
        long globalIndex = 0;

        for (int len = MIN_LEN; len <= MAX_LEN; len++) {

            long combinations = (long) Math.pow(base, len);

            long blockStart = globalIndex;
            long blockEnd = globalIndex + combinations;

            // If this length block is completely before our range — skip it
            if (blockEnd <= startIndex) {
                globalIndex += combinations;
                continue;
            }

            // If this block starts after our range — stop completely
            if (blockStart >= endIndex) {
                break;
            }

            // Compute local start and end inside this length block
            long localStart = Math.max(0, startIndex - blockStart);
            long localEnd = Math.min(combinations, endIndex - blockStart);

            for (long i = localStart; i < localEnd; i++) {

                String key = numberToKey(i, len);

                if (sha256(key).equals(targetHash)) {
                    return key;
                }
            }

            globalIndex += combinations;
        }

        return null;
    }

    // Convert number → base-N string
    private static String numberToKey(long num, int length) {
        char[] result = new char[length];
        int base = CHAR_SET.length();

        for (int i = length - 1; i >= 0; i--) {
            result[i] = CHAR_SET.charAt((int)(num % base));
            num /= base;
        }

        return new String(result);
    }

    public static long calculateKeyspaceSize() {
        long total = 0;
        int n = CHAR_SET.length();

        for (int len = MIN_LEN; len <= MAX_LEN; len++) {
            total += Math.pow(n, len);
        }

        return total;
    }

    public static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));

            StringBuilder hexString = new StringBuilder();

            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}