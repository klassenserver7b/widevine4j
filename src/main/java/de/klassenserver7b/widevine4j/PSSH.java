package de.klassenserver7b.widevine4j;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class PSSH {
    public static final int SIGNATURE = 0x70737368;
    public static final byte[] WIDEVINE_SYSTEM_UUID = {-19, -17, -117, -87, 121, -42, 74, -50, -93, -56, 39, -36, -43, 29, 33, -19};

    public static byte[] getData(byte[] psshBox) {
        if (psshBox == null) return null;
        if (psshBox.length < 8) return null;

        int length = ByteBuffer.allocate(4)
                .order(ByteOrder.BIG_ENDIAN)
                .put(psshBox, 0, 4)
                .flip()
                .getInt();

        if (length != psshBox.length) return null;

        int signature = ByteBuffer.allocate(4)
                .order(ByteOrder.BIG_ENDIAN)
                .put(psshBox, 4, 4)
                .flip()
                .getInt();

        if(signature != SIGNATURE) return null;

        byte[] systemUUID = Arrays.copyOfRange(psshBox, 12, 28);

        if(!Arrays.equals(systemUUID, WIDEVINE_SYSTEM_UUID)) return null;

        int dataSize = ByteBuffer.allocate(4)
                .order(ByteOrder.BIG_ENDIAN)
                .put(psshBox, 28, 4)
                .flip()
                .getInt();

        if(dataSize + 32 != psshBox.length) return null;

        return Arrays.copyOfRange(psshBox, 32, 32 + dataSize);
    }
}
