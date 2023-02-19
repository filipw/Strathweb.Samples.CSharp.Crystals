using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

var random = new SecureRandom();
var keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber1024);
var kyberKeyPairGenerator = new KyberKeyPairGenerator();
kyberKeyPairGenerator.Init(keyGenParameters);

// generate key pair for Alice
var aliceKeyPair = kyberKeyPairGenerator.GenerateKeyPair();

// get and view the keys
var alicePublic = (KyberPublicKeyParameters)aliceKeyPair.Public;
var alicePrivate = (KyberPrivateKeyParameters)aliceKeyPair.Private;
var pubEncoded = alicePublic.GetEncoded();
var privateEncoded = alicePrivate.GetEncoded();
Console.WriteLine("Alice's Public key: " + PrettyPrint(pubEncoded));
Console.WriteLine("Alice's Private key: " + PrettyPrint(privateEncoded));

// Bob encapsulates a new shared secret using Alice's public key
var bobKyberKemGenerator = new KyberKemGenerator(random);
var encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(alicePublic);
var bobSecret = encapsulatedSecret.GetSecret();
Console.WriteLine("Bob's Secret: " + PrettyPrint(bobSecret));

// cipher text produced by Bob and sent to Alice
var cipherText = encapsulatedSecret.GetEncapsulation();
Console.WriteLine("Cipher text: " + PrettyPrint(cipherText));

// Alice decapsulates a new shared secret using Alice's private key
var aliceKemExtractor = new KyberKemExtractor(alicePrivate);
var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);
Console.WriteLine("Alice's Secret: " + PrettyPrint(aliceSecret));

static string PrettyPrint(byte[] bytes) {
    var base64 = Convert.ToBase64String(bytes);
    if (base64.Length > 50)
        return $"{base64[..25]}...{base64[^25..]}";

    return base64;
}