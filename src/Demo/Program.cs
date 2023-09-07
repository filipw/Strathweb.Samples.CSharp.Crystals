using System.Text;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Spectre.Console;

var demo = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("Choose the [green]demo[/] to run?")
        .AddChoices(new[]
        {
            "Kyber", "Dilithium"
        }));

switch (demo)
{
    case "Kyber":
        RunKyber();
        break;
    case "Dilithium":
        RunDilithium();
        break;
    default:
        Console.WriteLine("Nothing selected!");
        break;
}

static void RunDilithium()
{
    Console.WriteLine("***************** DILITHIUM *******************");
    
    var raw = "Hello, Dilithium!";
    Console.WriteLine($"Raw Message: {raw}");

    var data = Hex.Encode(Encoding.ASCII.GetBytes(raw));
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

    // Console.WriteLine("Private key lengths");
    // Console.WriteLine($"Rho: {privateKey.Rho.Length}");
    // Console.WriteLine($"K: {privateKey.K.Length}");
    // Console.WriteLine($"Tr: {privateKey.Tr.Length}");
    // Console.WriteLine($"S1: {privateKey.S1.Length}");
    // Console.WriteLine($"S2: {privateKey.S2.Length}");
    // Console.WriteLine($"T0: {privateKey.T0.Length}");
    
    var aliceRecovered = new DilithiumSigner();
    var recoveredKey = RecoverPrivateKeyFromExport(privateKey.GetEncoded(), DilithiumParameters.Dilithium3);
    aliceRecovered.Init(true, recoveredKey);
    var signature2 = aliceRecovered.GenerateSignature(data);
    Console.WriteLine($"Signature (recovered): {PrettyPrint(signature2)}");
    
    // verify signature
    var bobReVerified = bob.VerifySignature(data, signature2);
    Console.WriteLine($"Successfully verified (recovered) signature? {verified}");
}

static DilithiumPrivateKeyParameters RecoverPrivateKeyFromExport(byte[] encodedPrivateKey, DilithiumParameters dilithiumParameters)
{
    const int seedBytes = 32;
    int s1Length;
    int s2Length;
    int t0Length;

    if (dilithiumParameters == DilithiumParameters.Dilithium2)
    {
        s1Length = 4 * 96; 
        s2Length = 4 * 96;
        t0Length = 4 * 416;
    } 
    else if (dilithiumParameters == DilithiumParameters.Dilithium3)
    {
        s1Length = 5 * 128;
        s2Length = 6 * 128;
        t0Length = 6 * 416;
    } 
    else if (dilithiumParameters == DilithiumParameters.Dilithium5)
    {
        s1Length = 7 * 96;
        s2Length = 8 * 96;
        t0Length = 8 * 416;
    }
    else
    {
        throw new NotSupportedException("Unsupported mode");
    }
    
    var rho = new byte[seedBytes]; // SeedBytes length
    var k = new byte[seedBytes]; // SeedBytes length
    var tr = new byte[seedBytes]; // SeedBytes length
    var s1 = new byte[s1Length]; // L * PolyEtaPackedBytes
    var s2 = new byte[s2Length]; // K * PolyEtaPackedBytes
    var t0 = new byte[t0Length]; // K * PolyT0PackedBytes

    var offset = 0;
    Array.Copy(encodedPrivateKey, offset, rho, 0, seedBytes);
    offset += seedBytes;
    Array.Copy(encodedPrivateKey, offset, k, 0, seedBytes);
    offset += seedBytes;
    Array.Copy(encodedPrivateKey, offset, tr, 0, seedBytes);
    offset += seedBytes;
    Array.Copy(encodedPrivateKey, offset, s1, 0, s1Length);
    offset += s1Length;
    Array.Copy(encodedPrivateKey, offset, s2, 0, s2Length);
    offset += s2Length;
    Array.Copy(encodedPrivateKey, offset, t0, 0, t0Length);
    offset += t0Length;
    
    // Take all remaining bytes as t1
    var remainingLength = encodedPrivateKey.Length - offset;
    var t1 = new byte[remainingLength];
    Array.Copy(encodedPrivateKey, offset, t1, 0, remainingLength);

    return new DilithiumPrivateKeyParameters(dilithiumParameters, rho, k, tr, s1, s2, t0, t1);
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

static void PrintPanel(string header, string[] data)
{
    var content = string.Join(Environment.NewLine, data);
    var panel = new Panel(content)
    {
        Header = new PanelHeader(header)
    };
    AnsiConsole.Write(panel);
}

static string PrettyPrint(byte[] bytes) {
    var base64 = Convert.ToBase64String(bytes);
    if (base64.Length > 50)
        return $"{base64[..25]}...{base64[^25..]}";

    return base64;
}