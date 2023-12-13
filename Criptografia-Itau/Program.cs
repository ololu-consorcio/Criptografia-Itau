using Criptografia_Itau;

try
{
    Console.WriteLine("\n=========================================");
    Console.WriteLine("Informe as informações recebidas no e-mail");
    Console.WriteLine("=========================================");

    Console.Write("\nClientId: ");
    string clientIdCifrado = Console.ReadLine().Trim();

    Console.Write("\nToken Temporário: ");
    string tokenCifrado = Console.ReadLine().Trim();

    Console.Write("\nChave Sessão: ");
    string chaveSessaoCifrada = Console.ReadLine().Trim();

    Console.Write("\nCaminho chave privada: ");
    string caminhoChavePrivada = Console.ReadLine().Trim();

    Console.WriteLine("\n=====================================");
    Console.WriteLine("    Processo de Decriptografia         ");
    Console.WriteLine("=====================================");

    // Decifra a chave de sessao AES com a chave RSA privada
    byte[] chaveSessaoDecifrada = Utils.DecriptografiaRsa(caminhoChavePrivada, chaveSessaoCifrada);
    // Decriptografa a credencial através da chave de sessão AES
    string clientIdDecifrada = Utils.DecriptografiaAes(chaveSessaoDecifrada, clientIdCifrado);
    Console.WriteLine("\nClient id decifrado com a chave de sessao AES:\n[ " + clientIdDecifrada + " ]");
    string tokenDecifrado = Utils.DecriptografiaAes(chaveSessaoDecifrada, tokenCifrado);
    Console.WriteLine("\nToken decifrado com a chave de sessao AES:\n[ " + tokenDecifrado + " ]");
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
}