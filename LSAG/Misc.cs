using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace LSAG
{
  public static class LSAGExts
  {
    public static BigInteger HexToUnsignedInteger(this string hex)
    {
      return BigInteger.Parse(("0" + hex).Replace(" ", "").Replace("\r\n", ""), System.Globalization.NumberStyles.HexNumber);
    }

    public static byte[] Concat(this byte[] a1, byte[] a2)
    {
      byte[] res = new byte[a1.Length + a2.Length];
      Buffer.BlockCopy(a1, 0, res, 0, a1.Length);
      Buffer.BlockCopy(a2, 0, res, a1.Length, a2.Length);
      return res;
    }

    public static BigInteger GenerateInteger(this RandomNumberGenerator rng, BigInteger max, int securityParameter = 64)
    { // The simple modular method from the NIST SP800-90A recommendation
      if (securityParameter < 64)
        throw new SecurityException("Given security parameter, " + securityParameter + ", is too low.");

      var bytesToRepresent = max.ToByteArray().Length;
      var bytes = new byte[bytesToRepresent + securityParameter / 8 + 1];
      rng.GetBytes(bytes);
      bytes[bytes.Length - 1] = 0;
      return BigInteger.Remainder(new BigInteger(bytes), max);
    }

    public static BigInteger Mod(this BigInteger x, BigInteger module)
    {
      return x >= 0 ? BigInteger.Remainder(x, module) : module + BigInteger.Remainder(x, module);
    }

    public static BigInteger FlipBit(this BigInteger number, int bit)
    {
      return number ^ (BigInteger.One << bit);
    }

    public static int BitLength(this BigInteger number)
    {
      return (int)Math.Ceiling(BigInteger.Log(number, 2));
    }
  }
}
