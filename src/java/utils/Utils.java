package src.java.utils;

public class Utils {

    //HexUtils
    private static final char[] int2hex = new char[]
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    //int a string
    public static String toString
            (int val)
    {
        StringBuilder buf = new StringBuilder (8);
        buf.append (int2hex[(val >> 28) & 0xF]);
        buf.append (int2hex[(val >> 24) & 0xF]);
        buf.append (int2hex[(val >> 20) & 0xF]);
        buf.append (int2hex[(val >> 16) & 0xF]);
        buf.append (int2hex[(val >> 12) & 0xF]);
        buf.append (int2hex[(val >>  8) & 0xF]);
        buf.append (int2hex[(val >>  4) & 0xF]);
        buf.append (int2hex[(val      ) & 0xF]);
        return buf.toString();
    }

    //array de bytes a string
    public static String toString
            (byte[] val)
    {
        return toString (val, 0, val.length);
    }

    //un pedazo de array de bytes a string
    public static String toString
            (byte[] val,
             int off,
             int len)
    {
        if (off < 0 || len < 0 || off + len > val.length)
        {
            throw new IndexOutOfBoundsException();
        }
        StringBuilder buf = new StringBuilder (2*len);
        while (len > 0)
        {
            buf.append (int2hex[(val[off] >> 4) & 0xF]);
            buf.append (int2hex[(val[off]     ) & 0xF]);
            ++ off;
            -- len;
        }
        return buf.toString();
    }

    //string a array de bytes
    public static byte[] toByteArray
            (String str)
    {
        int n = (str.length() + 1) / 2;
        byte[] val = new byte [n];
        toByteArray (str, val, 0, val.length);
        return val;
    }

    //string a byte array
    public static void toByteArray
            (String str,
             byte[] val,
             int off,
             int len)
    {
        if (off < 0 || len < 0 || off + len > val.length)
        {
            throw new IndexOutOfBoundsException();
        }
        int stroff = str.length() - 1;
        int valoff = off + len - 1;
        int result;
        while (len > 0 && stroff >= 0)
        {
            result = hex2int (str.charAt (stroff));
            -- stroff;
            if (stroff >= 0) result += hex2int (str.charAt (stroff)) << 4;
            -- stroff;
            val[valoff] = (byte) result;
            -- valoff;
            -- len;
        }
        while (len > 0)
        {
            val[valoff] = (byte) 0;
            -- valoff;
            -- len;
        }
    }

    //hexa a int
    private static int hex2int
            (char digit)
    {
        switch (digit)
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                return digit - '0';
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
                return digit - 'a' + 10;
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                return digit - 'A' + 10;
            default:
                throw new IllegalArgumentException
                        ("Not a hexadecimal digit: '" + digit + "'");
        }
    }

    //PackingUtils
    //byte array a long en big-endian
    public static long packLongBigEndian
    (byte[] src,
     int srcPos)
    {
        if (srcPos + 8 > src.length) throw new IndexOutOfBoundsException();
        long rv = 0L;
        for (int i = 0; i <= 7; ++ i)
            rv |= (src[srcPos+i] & 0xFFL) << ((7 - i)*8);
        return rv;
    }

    //byte array a int en big-endian
    public static int packIntBigEndian
            (byte[] src,
             int srcPos)
    {
        if (srcPos + 4 > src.length) throw new IndexOutOfBoundsException();
        int rv = 0;
        for (int i = 0; i <= 3; ++ i)
            rv |= (src[srcPos+i] & 0xFF) << ((3 - i)*8);
        return rv;
    }

    //int a byte array en big-endian
    public static void unpackIntBigEndian
            (int src,
             byte[] dst,
             int dstPos)
    {
        if (dstPos + 4 > dst.length) throw new IndexOutOfBoundsException();
        for (int i = 0; i <= 3; ++ i)
            dst[dstPos+i] = (byte)(src >> ((3 - i)*8));
    }

}
