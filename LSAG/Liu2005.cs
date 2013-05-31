using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace LSAG
{
  // This scheme is the "realization 2" from "Linkable Ring Signatures: Security Models and New Schemes"
  // by Joseph K. Liu and Duncan S. Wong - Computational Science and Its Applications–ICCSA 2005
  public class Liu2005 : LiuScheme<Liu2005.Signature>
  {
    public struct Signature : ILinkableSignature
    {
      public readonly BigInteger Y0, S;
      public readonly BigInteger[] C;

      public Signature(BigInteger Y0, BigInteger S, BigInteger[] C)
      {
        this.Y0 = Y0;
        this.S = S;
        this.C = C;
      }

      public bool IsLinked(ILinkableSignature other)
      {
        return Y0.Equals(((Signature)other).Y0);
      }
    }

    public override Signature GenerateSignature(byte[] message, BigInteger[] publicKeys, BigInteger privateKey, int identity)
    {
      var r = rng.GenerateInteger(GroupParameters.SubgroupSize);
      var c = new BigInteger[publicKeys.Length];

      var b = BigInteger.Zero;

      for (int i = 0; i < publicKeys.Length; ++i)
        if (i != identity)
        {
          c[i] = rng.GenerateInteger(GroupParameters.SubgroupSize);
          b = (b + c[i]).Mod(GroupParameters.SubgroupSize);
        }

      var x = (BigInteger[])publicKeys.Clone();
      x[identity] = GroupParameters.Generator;
      c[identity] = r;

      var a = mod.Pow(x, c);

      var L = ConcatInts(null, publicKeys);
      var h = Hash2(L);
      var y0 = mod.Pow(h, privateKey);
      var prefix = ConcatInts(L, y0).Concat(message);

      var h1 = Hash1(ConcatInts(prefix, a, mod.Pow(new[] { h, y0 }, new[] { r, b })));
      c[identity] = (h1 - b).Mod(GroupParameters.SubgroupSize);

      var s = (r - c[identity] * privateKey).Mod(GroupParameters.SubgroupSize);

      return new Signature(y0, s, c);
    }

    public override bool VerifySignature(byte[] message, BigInteger[] publicKeys, Signature signature)
    {
      int[,][] cache = null;
      var a = (mod.Pow(publicKeys, signature.C, ref cache) * mod.Pow(GroupParameters.Generator, signature.S)).Mod(GroupParameters.Prime);

      return VerifyA(message, signature, publicKeys, a);
    }


    public override bool VerifySignature(byte[] message, Liu2005.Signature signature, MultiExponentiation keyCache)
    {
      var a = (keyCache.Pow(signature.C) * mod.Pow(GroupParameters.Generator, signature.S)).Mod(GroupParameters.Prime);

      return VerifyA(message, signature, keyCache.Bases, a);
    }

    private bool VerifyA(byte[] message, Liu2005.Signature signature, BigInteger[] publicKeys, BigInteger a)
    {
      var b = BigInteger.Zero;
      for (int i = 0; i < signature.C.Length; ++i)
        b = (b + signature.C[i]).Mod(GroupParameters.SubgroupSize);

      var L = ConcatInts(null, publicKeys);
      var h = Hash2(L);
      var prefix = ConcatInts(L, signature.Y0).Concat(message);

      var h1 = Hash1(ConcatInts(prefix, a, mod.Pow(new[] { h, signature.Y0 }, new[] { signature.S, b })));

      return h1.Equals(b);
    }
  }
}
