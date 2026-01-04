using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace DatabaseEncryptor
{
    /// <summary>
    /// An advanced database encryption tool in C# using Entity Framework Core with SQL Server.
    /// This implements column-level encryption for sensitive data using AES-256 with PBKDF2 key derivation,
    /// salt for uniqueness, HMAC-SHA256 for integrity, and secure key management.
    /// It demonstrates complex cybersecurity practices for protecting data at rest in a database.
    /// </summary>
    public class EncryptedDbContext : DbContext
    {
        private const int SaltSize = 16; // 128-bit salt
        private const int KeySize = 32; // 256-bit key for AES
        private const int IvSize = 16; // 128-bit IV for AES-CBC
        private const int HmacKeySize = 32; // 256-bit key for HMAC
        private const int Iterations = 100000; // PBKDF2 iterations for key stretching
        private const int HmacSize = 32; // SHA256 produces 256-bit hash

        private readonly string _masterKey; // Master password for key derivation (in production, use secure storage like Azure Key Vault)

        public EncryptedDbContext(string masterKey)
        {
            _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
        }

        public DbSet<SensitiveData> SensitiveDatas { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                .AddJsonFile("appsettings.json")
                .Build();

            var connectionString = configuration.GetConnectionString("DefaultConnection");
            optionsBuilder.UseSqlServer(connectionString);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<SensitiveData>()
                .Property(e => e.EncryptedContent)
                .HasColumnType("varbinary(max)"); // Store encrypted data as binary
        }

        /// <summary>
        /// Encrypts and inserts sensitive data into the database.
        /// </summary>
        /// <param name="plaintext">The plaintext data to encrypt and store.</param>
        public void InsertSensitiveData(string plaintext)
        {
            if (string.IsNullOrEmpty(plaintext))
            {
                throw new ArgumentException("Plaintext cannot be null or empty.", nameof(plaintext));
            }

            // Generate random salt and IV
            byte[] salt = GenerateRandomBytes(SaltSize);
            byte[] iv = GenerateRandomBytes(IvSize);

            // Derive keys from master key and salt
            (byte[] encryptionKey, byte[] hmacKey) = DeriveKeys(_masterKey, salt);

            // Encrypt the plaintext
            byte[] ciphertext = EncryptData(Encoding.UTF8.GetBytes(plaintext), encryptionKey, iv);

            // Compute HMAC for integrity
            byte[] hmac = ComputeHmac(ciphertext, hmacKey);

            // Combine: salt + IV + HMAC + ciphertext
            byte[] encryptedPackage = CombineBytes(salt, iv, hmac, ciphertext);

            // Insert into database
            SensitiveDatas.Add(new SensitiveData { EncryptedContent = encryptedPackage });
            SaveChanges();

            Console.WriteLine("Data encrypted and inserted successfully.");
        }

        /// <summary>
        /// Retrieves and decrypts sensitive data from the database by ID.
        /// </summary>
        /// <param name="id">The ID of the record to retrieve.</param>
        /// <returns>The decrypted plaintext.</returns>
        public string RetrieveSensitiveData(int id)
        {
            var entity = SensitiveDatas.Find(id);
            if (entity == null)
            {
                throw new InvalidOperationException($"Record with ID {id} not found.");
            }

            byte[] encryptedPackage = entity.EncryptedContent;
            if (encryptedPackage.Length < SaltSize + IvSize + HmacSize)
            {
                throw new InvalidDataException("Encrypted data is too short or corrupted.");
            }

            // Extract components
            byte[] salt = new byte[SaltSize];
            byte[] iv = new byte[IvSize];
            byte[] storedHmac = new byte[HmacSize];
            byte[] ciphertext = new byte[encryptedPackage.Length - SaltSize - IvSize - HmacSize];

            Array.Copy(encryptedPackage, 0, salt, 0, SaltSize);
            Array.Copy(encryptedPackage, SaltSize, iv, 0, IvSize);
            Array.Copy(encryptedPackage, SaltSize + IvSize, storedHmac, 0, HmacSize);
            Array.Copy(encryptedPackage, SaltSize + IvSize + HmacSize, ciphertext, 0, ciphertext.Length);

            // Derive keys from master key and salt
            (byte[] encryptionKey, byte[] hmacKey) = DeriveKeys(_masterKey, salt);

            // Verify HMAC
            byte[] computedHmac = ComputeHmac(ciphertext, hmacKey);
            if (!CompareByteArrays(storedHmac, computedHmac))
            {
                throw new CryptographicException("Integrity check failed: Data may have been tampered with.");
            }

            // Decrypt
            byte[] plaintextBytes = DecryptData(ciphertext, encryptionKey, iv);
            return Encoding.UTF8.GetString(plaintextBytes);
        }

        private byte[] GenerateRandomBytes(int size)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[size];
                rng.GetBytes(bytes);
                return bytes;
            }
        }

        private (byte[] EncryptionKey, byte[] HmacKey) DeriveKeys(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256))
            {
                byte[] encryptionKey = pbkdf2.GetBytes(KeySize);
                byte[] hmacKey = pbkdf2.GetBytes(HmacKeySize);
                return (encryptionKey, hmacKey);
            }
        }

        private byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                using (var memoryStream = new MemoryStream())
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }
        }

        private byte[] DecryptData(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                using (var memoryStream = new MemoryStream(data))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var outputStream = new MemoryStream())
                {
                    cryptoStream.CopyTo(outputStream);
                    return outputStream.ToArray();
                }
            }
        }

        private byte[] ComputeHmac(byte[] data, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        private bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        private byte[] CombineBytes(params byte[][] arrays)
        {
            byte[] combined = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (var array in arrays)
            {
                Buffer.BlockCopy(array, 0, combined, offset, array.Length);
                offset += array.Length;
            }
            return combined;
        }
    }

    public class SensitiveData
    {
        public int Id { get; set; }
        public byte[] EncryptedContent { get; set; }
    }

    /// <summary>
    /// Example usage of the EncryptedDbContext.
    /// Ensure you have appsettings.json with "DefaultConnection" string.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            string masterKey = "StrongMasterKey123!"; // In production, secure this properly

            using (var context = new EncryptedDbContext(masterKey))
            {
                // Ensure database is created
                context.Database.EnsureCreated();

                // Insert example
                try
                {
                    context.InsertSensitiveData("This is sensitive information.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Insertion error: {ex.Message}");
                }

                // Retrieve example (assuming ID 1 exists)
                try
                {
                    string decrypted = context.RetrieveSensitiveData(1);
                    Console.WriteLine($"Decrypted data: {decrypted}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Retrieval error: {ex.Message}");
                }
            }
        }
    }
}