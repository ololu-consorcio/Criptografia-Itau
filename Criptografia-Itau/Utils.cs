using System.Security.Cryptography;
using System.Text;

namespace Criptografia_Itau
{
    public static class Utils
    {
        public static string ExtrairChaveRsaPem(string tipoChave, string arquivoChavesRsa)
        {
            try
            {
                using (var reader = new StreamReader(arquivoChavesRsa))
                {
                    StringBuilder sb = new StringBuilder();
                    bool inKey = false;
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (!inKey)
                        {
                            if (line.StartsWith("-----BEGIN ") && line.EndsWith(" " + tipoChave + " KEY-----"))
                            {
                                inKey = true;
                            }
                        }
                        else
                        {
                            if (line.StartsWith("-----END ") && line.EndsWith(" " + tipoChave + " KEY-----"))
                            {
                                break;
                            }
                            sb.Append(line);
                        }
                    }
                    return sb.ToString();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return null;
        }

        public static string DecriptografiaAes(byte[] key, string cipherText)
        {
            try
            {
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = key;
                    aesAlg.IV = new byte[16]; // Default IV with zeroes
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    byte[] cipherBytes = Convert.FromBase64String(cipherText);
                    using (var msDecrypt = new MemoryStream(cipherBytes))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                return srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return null;
        }

        public static byte[] DecriptografiaRsa(string caminhoChavePrivada, string dadosCifrados)
        {
            try
            {
                string chavePrivadaPem = ExtrairChaveRsaPem("PRIVATE", caminhoChavePrivada);
                byte[] chavePrivadaBytes = Convert.FromBase64String(chavePrivadaPem);

                using (RSA rsa = RSA.Create())
                {
                    rsa.ImportPkcs8PrivateKey(chavePrivadaBytes, out _);
                    byte[] dadosCifradosBytes = Convert.FromBase64String(dadosCifrados);
                    return rsa.Decrypt(dadosCifradosBytes, RSAEncryptionPadding.Pkcs1);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return null;
        }
    }
}
