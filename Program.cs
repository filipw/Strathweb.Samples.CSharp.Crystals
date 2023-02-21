using System.Text;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

RunKyber();
RunDilithium();

static void RunDilithium()
{
    Console.WriteLine("***************** DILITHIUM *******************");
    var data = Hex.Encode(Encoding.ASCII.GetBytes("Hello, Dilithium!"));
    Console.WriteLine($"Message: {PrettyPrint(data)}");

    var random = new SecureRandom();
    var keyGenParameters = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium3);
    var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
    dilithiumKeyPairGenerator.Init(keyGenParameters);

    var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();

    // get and view the keys
    var publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
    var privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
    var pubEncoded = publicKey.GetEncoded();
    var privateEncoded = privateKey.GetEncoded();
    Console.WriteLine($"Public key: {PrettyPrint(pubEncoded)}");
    Console.WriteLine($"Private key: {PrettyPrint(privateEncoded)}");

    // sign
    var alice = new DilithiumSigner();
    alice.Init(true, privateKey);
    var signature = alice.GenerateSignature(data);
    Console.WriteLine($"Signature: {PrettyPrint(signature)}");

    // verify signature
    var bob = new DilithiumSigner();
    bob.Init(false, publicKey);
    var verified = bob.VerifySignature(data, signature);
    Console.WriteLine($"Successfully verified? {verified}");
    Console.WriteLine("");
}

static void RunKyber() 
{
    Console.WriteLine("***************** KYBER *******************");
    var random = new SecureRandom();
    var keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber768);
    var kyberKeyPairGenerator = new KyberKeyPairGenerator();
    kyberKeyPairGenerator.Init(keyGenParameters);

    // generate key pair for Alice
    var aliceKeyPair = kyberKeyPairGenerator.GenerateKeyPair();

    // get and view the keys
    var alicePublic = (KyberPublicKeyParameters)aliceKeyPair.Public;
    var alicePrivate = (KyberPrivateKeyParameters)aliceKeyPair.Private;
    var pubEncoded = alicePublic.GetEncoded();
    var privateEncoded = alicePrivate.GetEncoded();
    Console.WriteLine($"Alice's Public key: {PrettyPrint(pubEncoded)}");
    Console.WriteLine($"Alice's Private key: {PrettyPrint(privateEncoded)}");

    // Bob encapsulates a new shared secret using Alice's public key
    var bobKyberKemGenerator = new KyberKemGenerator(random);
    var encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(alicePublic);
    var bobSecret = encapsulatedSecret.GetSecret();
    Console.WriteLine($"Bob's Secret: {PrettyPrint(bobSecret)}");

    // cipher text produced by Bob and sent to Alice
    var cipherText = encapsulatedSecret.GetEncapsulation();
    Console.WriteLine($"Cipher text: {PrettyPrint(cipherText)}");

    // Alice decapsulates a new shared secret using Alice's private key
    var aliceKemExtractor = new KyberKemExtractor(alicePrivate);
    var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);
    Console.WriteLine($"Alice's Secret: {PrettyPrint(aliceSecret)}");

    // Compare secrets
    var equal = bobSecret.SequenceEqual(aliceSecret);
    Console.WriteLine($"Secrets equal? {equal}");
    Console.WriteLine("");
}

static string PrettyPrint(byte[] bytes) {
    var base64 = Convert.ToBase64String(bytes);
    if (base64.Length > 50)
        return $"{base64[..25]}...{base64[^25..]}";

    return base64;
}