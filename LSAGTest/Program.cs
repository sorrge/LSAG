using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using LSAG;
using System.Diagnostics;
using System.Numerics;

namespace LSAGTest
{
  class Program
  {
    static void Main(string[] args)
    {
      TestMultiExp();

      var liu2005 = new Liu2005();
      TestLiu(liu2005);
      BenchmarkLiu(liu2005, 1);
      BenchmarkLiu(liu2005, 10);
      BenchmarkLiu(liu2005, 100);
      BenchmarkLiu(liu2005, 1000);
      
      Console.WriteLine();

      var liu2004 = new Liu2004();
      TestLiu(liu2004);
      BenchmarkLiu(liu2004, 1);
      BenchmarkLiu(liu2004, 10);
      BenchmarkLiu(liu2004, 100);
    }

    private static void TestMultiExp()
    {
      Console.Write("Testing multi-exponentiation");
      int k = 111;
      var seed = new byte[1000];
      var r = new Random();
      r.NextBytes(seed);
      var rnd = new HMACDRBG(seed);
      var mod = new Modular(new BigInteger(5555555566666777777));

      var g = Enumerable.Range(0, k).Select(i => rnd.GenerateInteger(BigInteger.One << r.Next(200) + 200)).ToArray();
      var me = new MultiExponentiation(mod.Modulus, g);

      for (int i = 0; i < 1000; ++i)
      {
        var e = Enumerable.Range(0, k).Select(j => rnd.GenerateInteger(BigInteger.One << r.Next(100) + 100)).ToArray();
        //var z = mod.Pow(g, e, ref cache);
        var z = me.Pow(e);
        var z2 = BigInteger.One;
        for(int j = 0; j < k; ++j)
          z2 = (z2 * BigInteger.ModPow(g[j], e[j], mod.Modulus)).Mod(mod.Modulus);

        if (!z.Equals(z2))
          Console.WriteLine("ouch");

        if (i % 100 == 0)
        {
          Console.Write('.');
        }

        r.NextBytes(seed);
        rnd.Reseed(seed);
      }

      Console.WriteLine();
    }

    static void BenchmarkLiu<T>(LiuScheme<T> lsag, int participants) where T : ILinkableSignature
    {
      Console.WriteLine("Benchmark for {0} participants", participants);
      lsag.GroupParameters = KnownGroupParameters.RFC5114_2_1_160;

      var message = "hi";
      var messageBytes = Encoding.UTF8.GetBytes(message);

      var keys = Enumerable.Range(0, participants).Select(i => lsag.GenerateKeyPair()).ToArray();
      var publicKeys = keys.Select(k => k[1]).ToArray();

      Console.WriteLine("Computing signatures");
      Stopwatch timer = new Stopwatch();
      timer.Start();
      var signatures = Enumerable.Range(0, participants).
        Select(i => lsag.GenerateSignature(messageBytes, publicKeys, keys[i][0], i)).ToArray();
      timer.Stop();
      Console.WriteLine("Generation took {0}, {1}s / participant, {2}s / participant^2", timer.Elapsed,
        timer.Elapsed.TotalSeconds / participants, timer.Elapsed.TotalSeconds / participants / participants);

      Console.WriteLine("Verifying signatures");
      timer.Restart();
      var cache = new MultiExponentiation(lsag.GroupParameters.Prime, publicKeys);
      if (signatures.All(s => lsag.VerifySignature(messageBytes, s, cache)))
        Console.WriteLine("OK");
      else
        Console.WriteLine("FAIL");

      timer.Stop();
      Console.WriteLine("Verification took {0}, {1}s / participant, {2}s / participant^2", timer.Elapsed,
        timer.Elapsed.TotalSeconds / participants, timer.Elapsed.TotalSeconds / participants / participants);
    }

    // This is a simple check that the implementation is not completely broken
    static void TestLiu<T>(LiuScheme<T> lsag) where T : ILinkableSignature
    {
      Console.WriteLine("Testing " + lsag);

      lsag.GroupParameters = KnownGroupParameters.ExampleDsa_160;
      Random rand = new Random();

      int participants = 5;
      var messages = new[] { "hi", "hi again", "this is another message" }.Select(Encoding.UTF8.GetBytes).ToArray();
      var keys = Enumerable.Range(0, participants).Select(i => lsag.GenerateKeyPair()).ToArray();
      foreach (var key in keys)
        if (BigInteger.ModPow(lsag.GroupParameters.Generator, key[0], lsag.GroupParameters.Prime) != key[1])
          Console.WriteLine("Key generation failed");

      var publicKeys = keys.Select(k => k[1]).ToArray();

      var signatures = new T[participants, messages.Length];
      for (int i = 0; i < participants; ++i)
        for (int j = 0; j < messages.Length; ++j)
        {
          signatures[i, j] = lsag.GenerateSignature(messages[j], publicKeys, keys[i][0], i);
          if (!lsag.VerifySignature(messages[j], publicKeys, signatures[i, j]))
            Console.WriteLine("Signature generation failed");

          for (int k = 0; k < messages.Length; ++k)
            if (lsag.VerifySignature(messages[k], publicKeys, signatures[i, j]) != (k == j))
              Console.WriteLine("Verification failed");

          if (signatures[i, j] is Liu2004.Signature)
          {
            var orig = (Liu2004.Signature)(ILinkableSignature)signatures[i, j];
            var tampered = new Liu2004.Signature(orig.C1.FlipBit(rand.Next(orig.C1.BitLength())), orig.S, orig.Ytilda);
            if (lsag.VerifySignature(messages[j], publicKeys, (T)(ILinkableSignature)tampered))
              Console.WriteLine("Tampering test failed");

            tampered = new Liu2004.Signature(orig.C1, orig.S, orig.Ytilda.FlipBit(rand.Next(orig.Ytilda.BitLength())));
            if (lsag.VerifySignature(messages[j], publicKeys, (T)(ILinkableSignature)tampered))
              Console.WriteLine("Tampering test failed");

            var s = (BigInteger[])orig.S.Clone();
            var t = rand.Next(s.Length);
            s[t] = s[t].FlipBit(rand.Next(s[t].BitLength()));
            tampered = new Liu2004.Signature(orig.C1, s, orig.Ytilda);
            if (lsag.VerifySignature(messages[j], publicKeys, (T)(ILinkableSignature)tampered))
              Console.WriteLine("Tampering test failed");
          }

          if (signatures[i, j] is Liu2005.Signature)
          {
            var orig = (Liu2005.Signature)(ILinkableSignature)signatures[i, j];
            var tampered = new Liu2005.Signature(orig.Y0, orig.S.FlipBit(rand.Next(orig.S.BitLength())), orig.C);
            if (lsag.VerifySignature(messages[j], publicKeys, (T)(ILinkableSignature)tampered))
              Console.WriteLine("Tampering test failed");

            tampered = new Liu2005.Signature(orig.Y0.FlipBit(rand.Next(orig.Y0.BitLength())), orig.S, orig.C);
            if (lsag.VerifySignature(messages[j], publicKeys, (T)(ILinkableSignature)tampered))
              Console.WriteLine("Tampering test failed");

            var s = (BigInteger[])orig.C.Clone();
            var t = rand.Next(s.Length);
            s[t] = s[t].FlipBit(rand.Next(s[t].BitLength()));
            tampered = new Liu2005.Signature(orig.Y0, orig.S, s);
            if (lsag.VerifySignature(messages[j], publicKeys, (T)(ILinkableSignature)tampered))
              Console.WriteLine("Tampering test failed");
          }
        }

      for (int i = 0; i < participants; ++i)
        for (int j = 0; j < messages.Length; ++j)
          for (int k = 0; k < participants; ++k)
            for (int l = 0; l < messages.Length; ++l)
              if (signatures[i, j].IsLinked(signatures[k, l]) != (i == k))
                Console.WriteLine("Linking failed");

      Console.WriteLine("Tests complete");
    }
  }
}
