using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace AsymetricEncryptionConsole
{
    class Program
    {
        private static readonly HttpClient Client = new();
        static async Task Main(string[] args)
        {            
            var bytesLengh = 2048;
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = await LoadKeys();

            //Parametros recomendados pela RFC do JWE
            var encryptDetail = new EncryptingCredentials(key: key, 
                                                          alg: SecurityAlgorithms.RsaOAEP, 
                                                          enc: SecurityAlgorithms.Aes128CbcHmacSha256);

            var tokenJwt = new SecurityTokenDescriptor()
            {
                Issuer = "www.andersongabriel.dev",
                Audience = "cartao-credito",
                Subject = new ClaimsIdentity(new[]
                {
                    //Dados do Cartao de credido : cc - Cartao de credito
                    new Claim("cc", "9000-8000-7000-6000")
                }),
                EncryptingCredentials = encryptDetail
            };

            var token = tokenHandler.CreateToken(tokenJwt);
            var jwe = tokenHandler.WriteToken(token);

            Console.WriteLine(jwe);

            var chaveDescriptografia = new EncryptingCredentials(key: key,
                                                          alg: SecurityAlgorithms.RsaOAEP,
                                                          enc: SecurityAlgorithms.Aes128CbcHmacSha256);

            var handler = new JsonWebTokenHandler();
            var result = handler.ValidateToken(jwe, new TokenValidationParameters()
            {
                ValidIssuer = "www.andersongabriel.dev",
                ValidAudience = "cartao-credito",
                RequireSignedTokens = false,
                TokenDecryptionKey = chaveDescriptografia.Key

            });

            Console.ReadLine();
        }

        //Busca a chave publica da api 
        public static async Task<JsonWebKey> LoadKeys()
        {
            var publicKeys = await Client.GetStringAsync("http://localhost:26276/jwks_e");
            var key = JsonWebKeySet.Create(publicKeys);
            return key.Keys.FirstOrDefault();
        }
    }
}
