using System.Text;
using System.Security.Cryptography;
using System.Collections;
using System.Net.Http.Headers;
using System.Net.Mime;

try
{
    string cipherTextIn;
    const int saltLabelLength = 8;
    byte[] myKey;
    byte[] myVector;
    byte[] mySalt = new byte[saltLabelLength];
    // Base64-encoded ciphertext that contains the string "Salted__" at the beginning followed by the 8 byte salt and the actual ciphertext.
    if (args.Length == 1 && args[0].ToLower().Equals("-e"))
    {
        Console.Write("Enter text to encrypt: ");
        Task<string> postString = UploadString(@"http://settersynology:9843/encrypt", Console.ReadLine());
        postString.Wait();
        cipherTextIn = postString.Result;
    }
    else if (args.Length == 1 && args[0].ToLower().Equals("-d"))
    {
        Console.Write("Enter text to decrypt: ");
        cipherTextIn = Console.ReadLine();
    }
    else
    {
        Task<string> getString = DownloadString(@"http://settersynology:9843/encrypt");
        getString.Wait();
        cipherTextIn = getString.Result;
    }
    Console.WriteLine("Encrypted text: " + cipherTextIn);
    byte[] objectIn = Convert.FromBase64String(cipherTextIn);
    int cipherTextLength = objectIn.Length - 16;
    byte[] cipherText = new byte[cipherTextLength];
    byte[] saltedLabel = new byte[saltLabelLength];
    using (MemoryStream ms = new MemoryStream(objectIn))
    {
        ms.Read(saltedLabel, 0, saltLabelLength);
        ms.Read(mySalt, 0, saltLabelLength);
        ms.Read(cipherText, 0, cipherTextLength);
    }
    if (Encoding.UTF8.GetString(saltedLabel).Equals("Salted__"))
    {
        //Console.WriteLine($"Label: {Encoding.UTF8.GetString(saltedLabel)}\r\nCipher Text: {Encoding.UTF8.GetString(cipherText)}\r\n Salt: {Encoding.UTF8.GetString(mySalt)}");
        //File.WriteAllText("log.txt", $"Label[{saltedLabel.Length}]: {Encoding.UTF8.GetString(saltedLabel)}\r\nCipher Text[{cipherText.Length}]: {Encoding.UTF8.GetString(cipherText)}\r\n Salt[{mySalt.Length}]: {Encoding.UTF8.GetString(mySalt)}");
        System.Resources.ResourceManager manager = new System.Resources.ResourceManager("Decrypt_CryptoJS.Properties.Resources", System.Reflection.Assembly.GetExecutingAssembly());
        DeriveKeyAndIV(manager.GetString("pass"), out myKey, out myVector, mySalt);
        string finalText = DecryptStringFromBytes_Aes(cipherText, myKey, myVector);
        Console.WriteLine("Decrypted Text: " + finalText);
    }
    else
    {
        Console.WriteLine("UNEXPECTED VALUE IN FIRST 8 BYTES");
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
}
Console.ReadKey();

static async Task<string> UploadString(string dest, string data)
{
    StringContent content = new StringContent(data);
    content.Headers.ContentType = new MediaTypeHeaderValue(MediaTypeNames.Text.Plain);
    HttpClient httpClient = new HttpClient();
    HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Post, dest);
    httpRequest.Content = content;
    HttpResponseMessage response = await httpClient.SendAsync(httpRequest);
    httpClient.Dispose();
    try
    {
        return (await response.EnsureSuccessStatusCode().Content.ReadAsStringAsync());
    }
    catch (HttpRequestException ex)
    {
        return $"{ex.Message}{Environment.NewLine}From: {ex.Source}";
    }
}

static async Task<string> DownloadString(string dest)
{
    HttpClient httpClient = new HttpClient();
    HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Get, dest);
    httpRequest.Headers.Accept.Clear();
    httpRequest.Headers.Add("Accept", MediaTypeNames.Text.Plain);
    HttpResponseMessage response = await httpClient.SendAsync(httpRequest);
    try
    {
        return (await response.EnsureSuccessStatusCode().Content.ReadAsStringAsync());
    }
    catch (HttpRequestException ex)
    {
        return $"{ex.Message}{Environment.NewLine}From: {ex.Source}";
    }
}

static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
{
    // Check arguments.
    if (cipherText == null || cipherText.Length <= 0)
        throw new ArgumentNullException("cipherText");
    if (Key == null || Key.Length <= 0)
        throw new ArgumentNullException("Key");
    if (IV == null || IV.Length <= 0)
        throw new ArgumentNullException("IV");

    // Declare the string used to hold
    // the decrypted text.
    string plaintext;

    // Create an Aes object
    // with the specified key and IV.
    using (Aes aesAlg = Aes.Create())
    {
        aesAlg.Key = Key;
        aesAlg.IV = IV;

        // Create a decryptor to perform the stream transform.
        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        // Create the streams used for decryption.
        using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        {
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {

                    // Read the decrypted bytes from the decrypting stream
                    // and place them in a string.
                    plaintext = srDecrypt.ReadToEnd();
                }
            }
        }
    }
    return plaintext;
}

static void DeriveKeyAndIV(string passphrase, out byte[] key, out byte[] iv, byte[] salt = null)
{
    // generate key and iv
    ArrayList concatenatedHashes = new ArrayList(48);
    byte[] password = Encoding.UTF8.GetBytes(passphrase);
    byte[] currentHash = new byte[0];

    //Might need to use SHA256 here depending on what version of OpenSSL is implemented by whatever version of cryptoJS Fremont is using.
    MD5 md5 = MD5.Create();
    //SHA256 sha256 = SHA256.Create();
    bool enoughBytesForKey = false;
    // See http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
    while (!enoughBytesForKey)
    {
        int preHashLength = salt != null ? currentHash.Length + password.Length + salt.Length : currentHash.Length + password.Length;
        byte[] preHash = new byte[preHashLength];
        Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
        Buffer.BlockCopy(password, 0, preHash, currentHash.Length, password.Length);
        if (salt != null)
            Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + password.Length, salt.Length);
        currentHash = md5.ComputeHash(preHash);
        concatenatedHashes.AddRange(currentHash);
        if (concatenatedHashes.Count >= 48)
            enoughBytesForKey = true;
    }
    key = new byte[32];
    iv = new byte[16];
    concatenatedHashes.CopyTo(0, key, 0, 32);
    concatenatedHashes.CopyTo(32, iv, 0, 16);
    //sha256.Clear();
    md5.Clear();
}